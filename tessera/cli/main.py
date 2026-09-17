"""``tessera`` - the command line.

Subcommands mirror the GUI exactly, because both drive the same Session.  If
you can click it you can script it, which is the property that decides whether
a tool survives contact with someone who has forty servers.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import List, Optional

from .. import __version__, branding
from ..core import expiry as expiry_mod
from ..core import fleet
from ..core import interview as iv
from ..core import qr as qr_mod
from ..core.audit import tally, verdict
from ..core.errors import TesseraError
from ..core.manager import Session
from ..core import backup as backup_mod
from ..core.models import InstallSpec
from ..core.plan import Plan, Step, StepStatus
from ..core.state import summary_line
from .ui import UI, human_age, human_bytes
from . import wizard

EXIT_OK, EXIT_ERROR, EXIT_BLOCKED, EXIT_AUDIT_FAILED = 0, 1, 2, 3


# --------------------------------------------------------------------------- #
# Shared plumbing
# --------------------------------------------------------------------------- #
def connect(ui: UI, args) -> Session:
    raw = (getattr(args, "server", "") or getattr(args, "target", "") or "")
    # A saved nickname wins over a hostname. The two namespaces cannot overlap
    # because a nickname may not contain @ : or / - see fleet.validate_name.
    target = fleet.resolve(raw)
    if getattr(args, "user", ""):
        target.user = args.user
    if getattr(args, "port", 0):
        target.port = args.port
    if getattr(args, "identity", ""):
        target.identity = args.identity

    password = None
    if getattr(args, "ask_sudo_password", False):
        password = getpass.getpass("sudo password for {}: ".format(
            target.display()))
    elif os.environ.get("TESSERA_SUDO_PASSWORD"):
        password = os.environ["TESSERA_SUDO_PASSWORD"]

    ui.info("Inspecting {} ...".format(target.display()))
    session = Session.connect(
        target, sudo_password=password,
        resolve_public_ip=not getattr(args, "offline", False),
        strict_host_keys=getattr(args, "strict_host_keys", False))
    if session.can_root:
        ui.ok("{}  -  {}".format(session.facts.summary(),
                                 summary_line(session.state)))
    else:
        ui.ok(session.facts.summary())
        ui.warn("No root on this target: {}".format(session.state_error))
        ui.note("Read-only commands still work. To make changes, re-run with "
                "--ask-sudo-password or connect as root.")
    if target.label:
        fleet.touch(target.label, os_summary=session.facts.summary(),
                    engines=session.state.installed_engines)
    # Anything the server revoked on its own while we were away.
    try:
        expired = session.reconcile_expiries()
        for entry in expired:
            ui.info("'{}' expired on {} and was revoked automatically.".format(
                entry["name"], entry["expired"]))
    except Exception:                                          # noqa: BLE001
        pass
    soon = []
    try:
        soon = session.expiring_soon(7)
    except Exception:                                          # noqa: BLE001
        pass
    for peer in soon:
        ui.warn("'{}' {}.".format(peer.name,
                                  expiry_mod.describe(peer.access_expires)))
    return session


def progress_printer(ui: UI, verbose: bool = False):
    """Print each step as it runs, in place when the terminal allows it."""
    def hook(step: Step, index: int, total: int) -> None:
        # Only the outcome is printed. Announcing a step and then repeating it
        # with a tick doubles the length of every install log for no gain.
        if step.status is StepStatus.RUNNING:
            if verbose:
                ui.out("  [{:>2}/{}] {} ...".format(index, total, step.title),
                       "muted")
                if step.why:
                    ui.note("        " + step.why)
            return
        if step.status is StepStatus.OK:
            ui.ok("  [{:>2}/{}] {}".format(index, total, step.title))
        elif step.status is StepStatus.SKIPPED:
            ui.note("  [{:>2}/{}] {} (skipped)".format(index, total, step.title))
        elif step.status is StepStatus.FAILED:
            ui.fail("  [{:>2}/{}] {}".format(index, total, step.title))
            if step.error:
                for line in step.error.strip().splitlines()[:8]:
                    ui.note("        " + line)
    return hook


def show_plan(ui: UI, plan: Plan, verbose: bool = False) -> None:
    ui.rule("Plan: {} step{}, {} change the server".format(
        len(plan), "" if len(plan) == 1 else "s", len(plan.mutating)))
    for i, step in enumerate(plan.steps, 1):
        ui.out("  {:>3}. [{}] {}".format(
            i, step.kind.value[:5].ljust(5), step.title))
        ui.note("       $ " + step.preview().replace("\n", "\n         "))
        if verbose and step.why:
            ui.note("       " + step.why)
    if plan.notes:
        ui.out()
        for n in plan.notes:
            ui.info(n)


def report_issues(ui: UI, issues) -> bool:
    """Print preflight issues.  Returns True if any are blocking."""
    blocking = False
    for level, engine, message in issues:
        tag = "[{}] ".format(engine) if engine else ""
        if level == "block":
            ui.fail(tag + message)
            blocking = True
        else:
            ui.warn(tag + message)
    return blocking


def save_config(ui: UI, name: str, content: str, outdir: str,
                show_qr: bool = True) -> str:
    """Write a client config with 0600 and optionally print its QR code."""
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, name)
    # Create with the right mode from the start; writing then chmod-ing leaves
    # a window where the key is world-readable.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    ui.ok("Saved {}".format(path))
    if show_qr and qr_mod.available() and name.endswith(".conf"):
        ui.out()
        ui.block(qr_mod.terminal(content))
        ui.note("Scan with the WireGuard app on your phone.")
    return path


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_install(ui: UI, args) -> int:
    session = connect(ui, args)
    spec = InstallSpec(target=session.target)
    if args.engine:
        spec.engines = list(args.engine)
        iv.mark_answered(spec, "engines")
    if args.peer:
        spec.first_peer = args.peer
        iv.mark_answered(spec, "first_peer")

    if args.yes:
        spec = iv.apply_profile(spec, args.profile or "balanced", session.facts)
        if not spec.engines:
            spec.engines = ["wireguard"]
        spec = iv.fill_defaults(spec, session.facts)
        if args.endpoint:
            spec.wireguard.endpoint = spec.openvpn.endpoint = args.endpoint
            iv.mark_answered(spec, "wireguard.endpoint", "openvpn.endpoint")
        if args.vpn_port:
            if "wireguard" in spec.engines:
                spec.wireguard.port = args.vpn_port
            else:
                spec.openvpn.port = args.vpn_port
    else:
        ui.out()
        spec = wizard.run(ui, spec, session.facts, profile=args.profile,
                          advanced=args.advanced)

    wizard.review(ui, spec, session.facts)

    issues = session.preflight(spec)
    if issues:
        ui.rule("Preflight")
        if report_issues(ui, issues):
            ui.out()
            ui.fail("Cannot continue. Nothing has been changed.")
            return EXIT_BLOCKED
        ui.out()

    plan, _ = session.build_install_plan(spec)
    if args.dry_run:
        show_plan(ui, plan, verbose=args.verbose)
        ui.out()
        ui.info("Dry run: nothing was executed.")
        return EXIT_OK

    if args.show_plan:
        show_plan(ui, plan, verbose=args.verbose)
        ui.out()
    if not args.yes and not ui.confirm(
            "Apply {} changes to {}?".format(
                len(plan.mutating), spec.target.display()), True):
        ui.info("Nothing was changed.")
        return EXIT_OK

    ui.rule("Installing")
    report, configs = session.install(
        spec, on_progress=progress_printer(ui, args.verbose))

    if not report.succeeded:
        ui.out()
        ui.fail("Install failed at: {}".format(
            report.failed_step.title if report.failed_step else "unknown step"))
        if report.rolled_back:
            ui.info("Rolled back {} completed step(s), so the server is as "
                    "it was.".format(len(report.rolled_back)))
        return EXIT_ERROR

    ui.out()
    ui.ok("Installed in {:.0f}s".format(report.duration))
    for note in plan.notes:
        ui.info(note)

    for key, content in configs.items():
        engine, _, peer = key.partition(":")
        ui.out()
        ui.rule("{} config for '{}'".format(engine, peer))
        ext = ".conf" if engine == "wireguard" else ".ovpn"
        save_config(ui, "{}-{}{}".format(engine, peer, ext), content,
                    args.out or os.path.join(os.getcwd(), "tessera-clients"),
                    show_qr=not args.no_qr)
    return EXIT_OK


def cmd_status(ui: UI, args) -> int:
    session = connect(ui, args)
    if not session.state.installed_engines:
        ui.warn("No Tessera-managed VPN on this server.")
        ui.note("Run 'tessera install' to set one up.")
        return EXIT_OK

    for name, info in session.status().items():
        ui.out()
        ui.rule(name)
        active = info.get("active")
        (ui.ok if active else ui.fail)(
            "service is {}".format("running" if active else "NOT running"))
        if info.get("error"):
            ui.warn(info["error"])
        rows = []
        # Map keys back to the names people actually gave their devices;
        # "jnkHuFtFeMUKicYK..." tells you nothing about whose phone that is.
        known = {peer.public_key: peer.name
                 for peer in session.list_peers(name) if peer.public_key}
        for p in info.get("peers", []):
            if name == "wireguard":
                key = p.get("public_key", "")
                rows.append([known.get(key) or (key[:16] + "..."),
                             p.get("allowed_ips", ""),
                             human_age(p.get("last_handshake", 0)),
                             "{} / {}".format(human_bytes(p.get("rx_bytes", 0)),
                                              human_bytes(p.get("tx_bytes", 0)))])
            elif name == "openvpn":
                rows.append([p.get("name", ""), p.get("virtual_address", ""),
                             p.get("connected_since", ""),
                             "{} / {}".format(human_bytes(p.get("rx_bytes", 0)),
                                              human_bytes(p.get("tx_bytes", 0)))])
            else:
                rows.append([p.get("name", ""),
                             ", ".join(p.get("addresses", [])),
                             "online" if p.get("online") else "offline",
                             p.get("os", "")])
        headers = {"wireguard": ["Peer", "Allowed IPs", "Handshake", "Rx / Tx"],
                   "openvpn": ["Name", "VPN address", "Since", "Rx / Tx"],
                   "tailscale": ["Name", "Addresses", "State", "OS"]}[name]
        ui.table(headers, rows)
    return EXIT_OK


def cmd_peer(ui: UI, args) -> int:
    # "peer" has three optional positionals in a row (action, name, target) and
    # argparse fills them left to right.  So "tessera peer list demo" put "demo"
    # in the name slot and silently fell back to localhost - a command that
    # looks right, runs, and reports on the wrong machine.  "list" takes no
    # name, so that slot is the target.
    if args.action == "list" and args.name and not args.target:
        args.target, args.name = args.name, ""
    if args.action in ("add", "remove") and not args.name:
        ui.fail("'{}' needs a device name.".format(args.action))
        ui.note("  tessera peer {} <name> [target]".format(args.action))
        return EXIT_ERROR

    session = connect(ui, args)
    engines = session.state.installed_engines
    if not engines:
        ui.fail("No Tessera-managed VPN on this server.")
        return EXIT_ERROR
    engine = args.engine_name or (engines[0] if len(engines) == 1 else "")
    if not engine and args.action != "list":
        ui.fail("This server runs {}. Say which with --engine.".format(
            " and ".join(engines)))
        return EXIT_ERROR

    if args.action == "list":
        for name in ([engine] if engine else engines):
            peers = session.list_peers(name)
            ui.out()
            ui.rule("{} - {} peer{}".format(name, len(peers),
                                            "" if len(peers) == 1 else "s"))
            rows = []
            for p in peers:
                if p.revoked:
                    state = "revoked"
                elif p.access_expires:
                    state = expiry_mod.describe(p.access_expires)
                else:
                    state = "active"
                rows.append([p.name,
                             p.address_v4 or p.fingerprint[:23] or "-",
                             p.created[:10], state, p.note or ""])
            ui.table(["Name", "Address", "Created", "State", "Note"], rows)
        return EXIT_OK

    if args.action == "add":
        peer, config = session.add_peer(
            engine, args.name, expires=args.expires, note=args.note)
        ui.ok("Added '{}' to {}".format(args.name, engine))
        if peer.access_expires:
            ui.info("Access {} ({}), revoked automatically by the server."
                    .format(expiry_mod.describe(peer.access_expires),
                            peer.access_expires))
        if peer.address_v4:
            ui.note("VPN address {}".format(peer.address_v4))
        if peer.expires:
            ui.note("certificate expires {}".format(peer.expires))
        ext = ".conf" if engine == "wireguard" else ".ovpn"
        ui.out()
        save_config(ui, "{}-{}{}".format(engine, args.name, ext), config,
                    args.out or os.path.join(os.getcwd(), "tessera-clients"),
                    show_qr=not args.no_qr)
        ui.out()
        ui.info("The private key in that file was generated here and was never "
                "sent to the server.")
        return EXIT_OK

    if args.action == "remove":
        if not args.yes and not ui.confirm(
                "Revoke '{}' from {}? The device stops working immediately."
                .format(args.name, engine), False):
            return EXIT_OK
        session.remove_peer(engine, args.name)
        ui.ok("Revoked '{}'".format(args.name))
        return EXIT_OK
    return EXIT_ERROR


def cmd_audit(ui: UI, args) -> int:
    session = connect(ui, args)
    ui.rule("Security audit")
    findings = session.audit()
    order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    for f in sorted(findings, key=lambda x: order.get(x.level, 9)):
        printer = {"fail": ui.fail, "warn": ui.warn,
                   "info": ui.info, "pass": ui.ok}[f.level]
        printer(f.title)
        if args.verbose or f.level in ("fail", "warn"):
            if f.detail:
                for line in f.detail.splitlines()[:6]:
                    ui.note("    " + line)
            if f.remedy:
                ui.note("    -> " + f.remedy)

    counts = tally(findings)
    result = verdict(findings)
    ui.out()
    ui.rule("Verdict")
    ui.kv([("passed", str(counts["pass"])), ("warnings", str(counts["warn"])),
           ("failures", str(counts["fail"]))])
    ui.out()
    if result == "pass":
        ui.ok("No problems found.")
        return EXIT_OK
    if result == "warn":
        ui.warn("Some things could be tightened.")
        return EXIT_OK
    ui.fail("This server has problems that need attention.")
    ui.note("A single failure fails the audit. Averaging one fatal flaw with "
            "nine passes into a 'B' would be comforting and wrong.")
    return EXIT_AUDIT_FAILED


def cmd_uninstall(ui: UI, args) -> int:
    session = connect(ui, args)
    installed = session.state.installed_engines
    if not installed:
        ui.warn("Nothing to remove: no Tessera-managed install here.")
        ui.note("Tessera only removes what it installed. If you set a VPN up "
                "by hand it cannot know what to touch, and will not guess.")
        return EXIT_OK

    targets = list(args.engine) if args.engine else installed
    plan = session.build_uninstall_plan(
        targets, purge_packages=not args.keep_packages,
        keep_backups=args.keep_backups,
        remove_hardening=not args.keep_hardening)

    show_plan(ui, plan, verbose=args.verbose)
    ui.out()
    if args.dry_run:
        ui.info("Dry run: nothing was executed.")
        return EXIT_OK

    ui.warn("This removes {} and shreds its key material.".format(
        " and ".join(targets)))
    ui.note("Anything that existed on this server before Tessera ran is left "
            "alone - that is what the inventory is for.")
    if not args.yes:
        typed = ui.ask("Type the word REMOVE to confirm", "")
        if typed != "REMOVE":
            ui.info("Nothing was changed.")
            return EXIT_OK

    ui.rule("Removing")
    report = session.uninstall(
        targets, purge_packages=not args.keep_packages,
        keep_backups=args.keep_backups,
        remove_hardening=not args.keep_hardening,
        on_progress=progress_printer(ui, args.verbose))
    ui.out()
    if report.succeeded:
        ui.ok("Removed cleanly in {:.0f}s".format(report.duration))
        ui.note("Client config files on your own machine are untouched; "
                "delete those yourself.")
        return EXIT_OK
    ui.fail("Removal stopped at: {}".format(
        report.failed_step.title if report.failed_step else "unknown"))
    ui.note("Re-run to continue: the inventory still records what is left.")
    return EXIT_ERROR


def cmd_doctor(ui: UI, args) -> int:
    session = connect(ui, args)
    f = session.facts
    ui.rule("Target")
    ui.kv([("OS", "{} {}".format(f.os_name or f.os_id, f.version_id)),
           ("Family / pkg", "{} / {}".format(f.family or "?", f.pkg or "?")),
           ("Kernel", f.kernel), ("Arch", f.arch),
           ("Init", f.init or "unknown"),
           ("Virtualisation", f.virt or "none (bare metal or full VM)"),
           ("Default NIC", f.nic or "not detected"),
           ("Public IPv4", f.public_ipv4 or "not detected"),
           ("Private IPv4", f.private_ipv4 or "-"),
           ("Behind NAT", "yes" if f.behind_nat else "no"),
           ("IPv6", "available" if f.has_ipv6 else "disabled"),
           ("/dev/net/tun", "present" if f.has_tun else "MISSING"),
           ("Firewall", f.firewall), ("SELinux", "enforcing" if f.selinux else "no"),
           ("Already installed", ", ".join(
               "{} {}".format(k, v) for k, v in f.installed.items()) or "none"),
           ("Tessera state", "unknown - {}".format(session.state_error)
            if session.state_error else summary_line(session.state))])
    ui.out()
    spec = InstallSpec(target=session.target)
    spec.engines = list(args.engine) if args.engine else ["wireguard", "openvpn",
                                                          "tailscale"]
    spec = iv.fill_defaults(spec, f)
    ui.rule("Compatibility")
    issues = session.preflight(spec)
    if not issues:
        ui.ok("No problems. Every engine can be installed here.")
        return EXIT_OK
    blocked = report_issues(ui, issues)
    return EXIT_BLOCKED if blocked else EXIT_OK


def cmd_export(ui: UI, args) -> int:
    """Re-issue a client config for an existing peer.

    Only possible for OpenVPN, and only if you still hold the key: WireGuard
    private keys exist on exactly one machine by design, so if you lost the
    config the honest answer is to make a new peer, not to pretend we can
    recover it.
    """
    session = connect(ui, args)
    peers = session.list_peers(args.engine_name or "")
    match = next((p for p in peers if p.name == args.name), None)
    if match is None:
        ui.fail("No peer named '{}'".format(args.name))
        return EXIT_ERROR
    ui.fail("Tessera cannot re-export '{}'.".format(args.name))
    ui.note("Its private key was generated on your machine and never stored "
            "anywhere else - that is the point of the design. Create a "
            "replacement peer and revoke this one:")
    ui.note("  tessera peer add {} --engine {}".format(
        args.name + "-new", match.engine))
    ui.note("  tessera peer remove {} --engine {}".format(
        args.name, match.engine))
    return EXIT_ERROR



def cmd_servers(ui: UI, args) -> int:
    """The address book. No secrets live here - see core/fleet.py."""
    if args.action == "list":
        book = fleet.load()
        if args.names:
            for name in book.names():
                print(name)
            return EXIT_OK
        servers = book.all()
        if not servers:
            ui.warn("No servers saved yet.")
            ui.note("tessera servers add prod root@vpn.example.com")
            return EXIT_OK
        rows = []
        for srv in servers:
            rows.append([srv.name, srv.display(),
                         srv.last_os or "-",
                         ", ".join(srv.last_engines) or "-",
                         (srv.last_seen or "never")[:10],
                         srv.note or ""])
        ui.table(["Name", "Target", "Last seen OS", "Engines", "Seen", "Note"],
                 rows)
        ui.out()
        ui.note("Stored at {} (mode 0600). It holds no keys or "
                "passwords.".format(fleet.path()))
        return EXIT_OK

    if args.action == "add":
        if not args.name or not args.location:
            ui.fail("usage: tessera servers add <name> <user@host[:port]>")
            return EXIT_ERROR
        srv = fleet.add(args.name, args.location, note=args.note,
                        tags=args.tag or [], identity=args.identity,
                        overwrite=args.force)
        ui.ok("Saved '{}' -> {}".format(srv.name, srv.display()))
        ui.note("Use it anywhere a target is accepted: tessera status {}"
                .format(srv.name))
        return EXIT_OK

    if args.action == "remove":
        fleet.remove(args.name)
        ui.ok("Removed '{}' from the server book.".format(args.name))
        ui.note("Nothing on the server itself was touched.")
        return EXIT_OK
    return EXIT_ERROR


def cmd_adopt(ui: UI, args) -> int:
    """Take over a VPN that something else installed."""
    session = connect(ui, args)
    ui.rule("Looking for an existing VPN")
    found = session.discover()
    if not found:
        ui.warn("No WireGuard, OpenVPN or Tailscale install found here.")
        ui.note("If you expected one, check it is in the usual place: "
                "/etc/wireguard or /etc/openvpn/server.")
        return EXIT_OK

    already = set(session.state.installed_engines)
    for line in adopt_summary(found):
        ui.ok(line)
    new = [k for k in found if k not in already]
    if not new:
        ui.out()
        ui.info("Tessera already manages everything it found here.")
        return EXIT_OK
    if already:
        ui.note("Already managed, will be left alone: {}".format(
            ", ".join(sorted(already))))

    ui.out()
    ui.info("Adopting writes an inventory describing what is already here.")
    ui.note("Nothing on the server is changed, restarted or reconfigured.")
    ui.note("Packages and system settings are recorded as pre-existing, so "
            "'tessera uninstall' will never remove them.")
    ui.out()
    if not args.yes and not ui.confirm(
            "Adopt {} on {}?".format(" and ".join(new), session.target.display()),
            True):
        ui.info("Nothing was changed.")
        return EXIT_OK

    engines, warnings = session.adopt(found)
    ui.out()
    ui.ok("Adopted {}".format(" and ".join(engines)))
    for warning in warnings:
        ui.warn(warning)
    ui.out()
    peers = session.list_peers()
    ui.info("{} peer(s) imported. 'tessera status' and 'tessera peer add' "
            "now work on this server.".format(len(peers)))
    ui.note("Existing peers' private keys live on their own devices, as they "
            "should, so Tessera cannot re-export their configs. New peers it "
            "creates are unaffected.")
    return EXIT_OK


def adopt_summary(found):
    from ..core.adopt import summarise
    return summarise(found)


def cmd_verify(ui: UI, args) -> int:
    """Has anything drifted from the inventory?"""
    session = connect(ui, args)
    ui.rule("Verifying {}".format(session.target.display()))
    findings = session.verify()
    order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    for f in sorted(findings, key=lambda x: order.get(x.level, 9)):
        {"fail": ui.fail, "warn": ui.warn, "info": ui.info,
         "pass": ui.ok}[f.level](f.title)
        if f.level in ("fail", "warn") or args.verbose:
            for line in (f.detail or "").splitlines()[:8]:
                ui.note("    " + line)
            if f.remedy:
                ui.note("    -> " + f.remedy)

    problems = [f for f in findings if f.is_problem]
    if not problems:
        return EXIT_OK
    if not args.fix:
        ui.out()
        plan = session.fixable()
        if any(plan.values()):
            ui.info("Some of this can be reconciled: "
                    "'tessera verify {} --fix'".format(
                        args.server or args.target or ""))
        return EXIT_AUDIT_FAILED

    plan = session.fixable()
    ui.out()
    ui.rule("Repair")
    if not any(plan.values()):
        ui.warn("Nothing here can be fixed automatically.")
        ui.note("Repair only ever edits Tessera's inventory. It will not add "
                "or remove access on the server, because a repair tool that "
                "can hand out access is one nobody should run unattended.")
        return EXIT_AUDIT_FAILED
    for name in plan["import"]:
        ui.note("import into the inventory: {}".format(name))
    for name in plan["forget"]:
        ui.note("mark as revoked: {}".format(name))
    ui.out()
    if not args.yes and not ui.confirm("Apply these inventory changes?", True):
        return EXIT_OK
    changed = session.apply_fix()
    for line in changed:
        ui.ok(line)
    ui.out()
    ui.ok("Inventory reconciled. The server itself was not modified.")
    return EXIT_OK


def cmd_backup(ui: UI, args) -> int:
    session = connect(ui, args)
    ui.rule("Backing up {}".format(session.target.display()))
    ui.info("The archive will contain private keys, including the OpenVPN CA "
            "if there is one, so it is always encrypted.")
    passphrase = _ask_passphrase(ui, confirm=True)

    blob, manifest = session.backup(passphrase)
    out = args.out or "tessera-{}-{}.backup".format(
        (session.target.label or session.facts.os_id or "server"),
        manifest.created[:10])
    backup_mod.write(out, blob)
    ui.out()
    ui.ok("Wrote {} ({:.0f} KB)".format(out, len(blob) / 1024.0))
    ui.kv([("contents", manifest.summary()),
           ("paths", ", ".join(manifest.paths))])
    ui.out()
    ui.note("Keep this somewhere you would keep a password database. Anyone "
            "with the file and the passphrase can impersonate your server.")
    ui.note("Restore with: tessera restore {} <target>".format(out))
    return EXIT_OK


def cmd_restore(ui: UI, args) -> int:
    blob = backup_mod.read(args.archive)
    manifest = backup_mod.peek(blob)
    ui.rule("Restore")
    ui.kv([("archive", args.archive),
           ("taken from", manifest.server or "unknown"),
           ("on", manifest.created[:19].replace("T", " ")),
           ("contents", manifest.summary()),
           ("by", "Tessera {}".format(manifest.tessera_version or "?"))])
    ui.out()

    session = connect(ui, args)
    existing = session.state.installed_engines
    if existing and not args.force:
        ui.fail("{} already runs {}.".format(
            session.target.display(), " and ".join(existing)))
        ui.note("Restoring would overwrite it. Pass --force if that is what "
                "you want, after taking a backup of what is there now.")
        return EXIT_BLOCKED

    ui.warn("This overwrites {} on the target.".format(
        ", ".join(manifest.paths)))
    if args.dry_run:
        payload, _ = backup_mod.unseal(blob, _ask_passphrase(ui))
        ui.out()
        ui.rule("Would restore")
        for name in backup_mod.contents(payload)[:40]:
            ui.note("  " + name)
        ui.out()
        ui.info("Dry run: nothing was written.")
        return EXIT_OK

    if not args.yes:
        typed = ui.ask("Type RESTORE to confirm", "")
        if typed != "RESTORE":
            ui.info("Nothing was changed.")
            return EXIT_OK

    passphrase = _ask_passphrase(ui)
    manifest, changes = session.restore(
        blob, passphrase, new_endpoint=args.endpoint)
    ui.out()
    ui.ok("Restored {}".format(manifest.summary()))
    for line in changes:
        ui.info("endpoint updated - {}".format(line))
    ui.out()
    ui.warn("Start the services when you are ready:")
    for engine in manifest.engines:
        unit = {"wireguard": "wg-quick@wg0",
                "openvpn": "openvpn-server@server",
                "tailscale": "tailscaled"}.get(engine, engine)
        ui.note("  systemctl enable --now {}".format(unit))
    if args.endpoint:
        ui.out()
        ui.warn("Existing client configs still point at the old address.")
        ui.note("Their keys are unchanged and still valid, but each device "
                "needs its Endpoint line updated to {} before it will "
                "connect. Tessera cannot edit files on other people's "
                "machines.".format(args.endpoint))
    return EXIT_OK


def _ask_passphrase(ui: UI, confirm: bool = False) -> str:
    import getpass
    env = os.environ.get("TESSERA_BACKUP_PASSPHRASE")
    if env:
        return env
    while True:
        first = getpass.getpass("Passphrase: ")
        if len(first) < 8:
            ui.fail("Use at least 8 characters.")
            continue
        if not confirm:
            return first
        again = getpass.getpass("Passphrase again: ")
        if first != again:
            ui.fail("They do not match.")
            continue
        return first


def cmd_watch(ui: UI, args) -> int:
    """A live view of who is connected."""
    import time
    session = connect(ui, args)
    if not session.state.installed_engines:
        ui.fail("No Tessera-managed VPN on this server.")
        return EXIT_ERROR
    ui.out()
    ui.note("Refreshing every {}s. Ctrl-C to stop.".format(args.interval))
    try:
        while True:
            status = session.status()
            lines = _render_watch(session, status)
            sys.stdout.write("\033[H\033[J" if ui.color else "\n")
            sys.stdout.write(lines)
            sys.stdout.flush()
            if args.once:
                return EXIT_OK
            time.sleep(max(2, args.interval))
    except KeyboardInterrupt:
        ui.out()
        return EXIT_OK


def _render_watch(session, status) -> str:
    import time
    out = []
    out.append("{}  -  {}\n".format(session.target.display(),
                                    time.strftime("%H:%M:%S")))
    for name, info in status.items():
        mark = "up" if info.get("active") else "DOWN"
        peers = info.get("peers", [])
        if name == "wireguard":
            online = sum(1 for p in peers
                         if p.get("last_handshake") and
                         time.time() - p["last_handshake"] < 180)
            out.append("\n  {}  {}  {} of {} peers active\n".format(
                name, mark, online, len(peers)))
            known = {p.public_key: p.name for p in session.list_peers(name)}
            for p in peers:
                out.append("    {:<16} {:<22} {:>10}  {:>10} down  {:>10} up\n"
                           .format(known.get(p.get("public_key"), "?")[:16],
                                   p.get("allowed_ips", "")[:22],
                                   human_age(p.get("last_handshake", 0)),
                                   human_bytes(p.get("rx_bytes", 0)),
                                   human_bytes(p.get("tx_bytes", 0))))
        else:
            out.append("\n  {}  {}  {} peer(s)\n".format(name, mark, len(peers)))
            for p in peers:
                out.append("    {:<16} {}\n".format(
                    str(p.get("name", ""))[:16],
                    p.get("virtual_address") or
                    ", ".join(p.get("addresses", []))))
    if not any(status.values()):
        out.append("\n  (nothing reporting)\n")
    return "".join(out)


def cmd_demo(ui: UI, args) -> int:
    """Manage the simulated server."""
    from ..core import demo
    if args.action == "reset":
        if demo.reset():
            ui.ok("The simulated server is back to a clean Ubuntu 24.04 box.")
        else:
            ui.info("The simulated server was already clean.")
        return EXIT_OK
    ui.kv([("state file", demo.state_path()),
           ("exists", "yes" if os.path.exists(demo.state_path()) else "no")])
    ui.out()
    ui.note("Try: tessera install demo   then   tessera status demo")
    ui.note("Reset it with: tessera demo reset")
    return EXIT_OK


def cmd_completions(ui: UI, args) -> int:
    """Print a shell completion script."""
    from .completions import render
    sys.stdout.write(render(args.shell, build_parser()))
    return EXIT_OK


def cmd_gui(ui: UI, args) -> int:
    try:
        from ..gui.app import main as gui_main
    except ImportError as exc:
        ui.fail("The GUI needs PyQt6, which is not installed.")
        ui.note("pip install 'tessera-vpn[gui]'   (or: pip install PyQt6)")
        ui.note(str(exc))
        return EXIT_ERROR
    return gui_main(sys.argv[:1])


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tessera",
        description="{}  -  {}".format(branding.TAGLINE, branding.DESCRIPTION),
        epilog="Docs: {}".format(branding.REPO),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version",
                   version="tessera {}".format(__version__))
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="explain each step as it runs")
    p.add_argument("--no-color", action="store_true")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    def add_target(sp, default_local=True):
        sp.add_argument("target", nargs="?", default="",
                        help="saved name, user@host[:port], or omit for this "
                             "machine")
        # An explicit flag as well as the positional. Commands like
        # `peer add guest --expires 14d prod` put a positional after options,
        # and argparse before Python 3.12 cannot reliably parse that - it
        # reports "unrecognized arguments: prod". `-s prod` always works, and
        # reads better anyway.
        sp.add_argument("-s", "--server", dest="server", default="",
                        help="the server to act on (same as the positional)")
        sp.add_argument("--user", default="", help="SSH user")
        sp.add_argument("--port", type=int, default=0, help="SSH port")
        sp.add_argument("-i", "--identity", default="", help="SSH key file")
        sp.add_argument("--ask-sudo-password", action="store_true",
                        help="prompt for the remote sudo password")
        sp.add_argument("--offline", action="store_true",
                        help="skip public IP lookup")
        sp.add_argument("--strict-host-keys", action="store_true",
                        help="refuse unknown SSH host keys instead of "
                             "recording them on first use")

    # install
    sp = sub.add_parser("install", help="install and configure a VPN")
    add_target(sp)
    sp.add_argument("-e", "--engine", action="append",
                    choices=["wireguard", "openvpn", "tailscale"],
                    help="repeatable; omit to be asked")
    sp.add_argument("--profile", choices=list(iv.PROFILES), default="")
    sp.add_argument("--peer", default="", help="name for the first device")
    sp.add_argument("--endpoint", default="", help="address clients connect to")
    sp.add_argument("--vpn-port", dest="vpn_port", type=int, default=0,
                    help="port the VPN itself listens on")
    sp.add_argument("-y", "--yes", action="store_true",
                    help="accept every default and do not prompt")
    sp.add_argument("--advanced", action="store_true",
                    help="ask the advanced questions too")
    sp.add_argument("--dry-run", action="store_true",
                    help="print the plan and exit without changing anything")
    sp.add_argument("--show-plan", action="store_true",
                    help="print the plan, then ask to apply it")
    sp.add_argument("-o", "--out", default="",
                    help="directory for generated client configs")
    sp.add_argument("--no-qr", action="store_true")
    sp.set_defaults(func=cmd_install)

    # status
    sp = sub.add_parser("status", help="show what is running and who is connected")
    add_target(sp)
    sp.set_defaults(func=cmd_status)

    # peer
    sp = sub.add_parser("peer", help="add, list or revoke client devices")
    sp.add_argument("action", choices=["add", "list", "remove"])
    sp.add_argument("name", nargs="?", default="")
    add_target(sp)
    sp.add_argument("-e", "--engine", dest="engine_name",
                    choices=["wireguard", "openvpn", "tailscale"], default="")
    sp.add_argument("--expires", default="",
                    help="revoke automatically after this long: 14d, 2w, 6m, "
                         "or a date like 2026-12-31")
    sp.add_argument("--note", default="")
    sp.add_argument("-o", "--out", default="")
    sp.add_argument("--no-qr", action="store_true")
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_peer)

    # audit
    sp = sub.add_parser("audit", help="check the server's security posture")
    add_target(sp)
    sp.set_defaults(func=cmd_audit)

    # uninstall
    sp = sub.add_parser("uninstall", help="remove cleanly, shredding key material")
    add_target(sp)
    sp.add_argument("-e", "--engine", action="append",
                    choices=["wireguard", "openvpn", "tailscale"],
                    help="remove only this engine; omit for everything")
    sp.add_argument("--keep-packages", action="store_true",
                    help="leave installed packages in place")
    sp.add_argument("--keep-hardening", action="store_true",
                    help="leave the hardening settings applied")
    sp.add_argument("--keep-backups", action="store_true",
                    help="keep /etc/tessera and its state backups")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_uninstall)

    # doctor
    sp = sub.add_parser("doctor", help="inspect a server without changing it")
    add_target(sp)
    sp.add_argument("-e", "--engine", action="append",
                    choices=["wireguard", "openvpn", "tailscale"])
    sp.set_defaults(func=cmd_doctor)

    # export
    sp = sub.add_parser("export", help="re-issue a client config (see notes)")
    sp.add_argument("name")
    add_target(sp)
    sp.add_argument("-e", "--engine", dest="engine_name", default="")
    sp.set_defaults(func=cmd_export)

    # servers
    sp = sub.add_parser("servers", help="save and list the machines you manage")
    sp.add_argument("action", choices=["list", "add", "remove"], nargs="?",
                    default="list")
    sp.add_argument("name", nargs="?", default="")
    sp.add_argument("location", nargs="?", default="",
                    help="user@host[:port] when adding")
    sp.add_argument("--note", default="")
    sp.add_argument("--tag", action="append")
    sp.add_argument("-i", "--identity", default="")
    sp.add_argument("--force", action="store_true", help="replace an existing entry")
    sp.add_argument("--names", action="store_true",
                    help="print names only, for shell completion")
    sp.set_defaults(func=cmd_servers)

    # adopt
    sp = sub.add_parser("adopt",
                        help="manage a VPN that another installer set up")
    add_target(sp)
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_adopt)

    # verify
    sp = sub.add_parser("verify", help="check the server still matches the inventory")
    add_target(sp)
    sp.add_argument("--fix", action="store_true",
                    help="reconcile the inventory (never changes the server)")
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_verify)

    # backup
    sp = sub.add_parser("backup", help="encrypted archive of keys and config")
    add_target(sp)
    sp.add_argument("-o", "--out", default="", help="output file")
    sp.set_defaults(func=cmd_backup)

    # restore
    sp = sub.add_parser("restore", help="rebuild a server from a backup")
    sp.add_argument("archive")
    add_target(sp)
    sp.add_argument("--endpoint", default="",
                    help="new public address, when migrating to another host")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing install")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_restore)

    # watch
    sp = sub.add_parser("watch", help="live view of who is connected")
    add_target(sp)
    sp.add_argument("--interval", type=int, default=5)
    sp.add_argument("--once", action="store_true")
    sp.set_defaults(func=cmd_watch)

    # demo
    sp = sub.add_parser("demo", help="the simulated server you can practise on")
    sp.add_argument("action", choices=["info", "reset"], nargs="?",
                    default="info")
    sp.set_defaults(func=cmd_demo)

    # completions
    sp = sub.add_parser("completions", help="print a shell completion script")
    sp.add_argument("shell", choices=["bash", "zsh", "fish"])
    sp.set_defaults(func=cmd_completions)

    # gui
    sp = sub.add_parser("gui", help="launch the desktop application")
    sp.set_defaults(func=cmd_gui)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ui = UI(quiet=args.quiet, no_color=args.no_color)

    if not getattr(args, "command", None):
        ui.banner(__version__)
        parser.print_help()
        return EXIT_OK

    if args.command not in ("gui",):
        ui.banner(__version__)

    try:
        return args.func(ui, args)
    except TesseraError as exc:
        ui.error(exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        ui.out()
        ui.warn("Interrupted. Nothing further was changed.")
        return EXIT_ERROR
    except Exception as exc:                                   # noqa: BLE001
        ui.error(exc)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

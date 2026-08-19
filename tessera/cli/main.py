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
from ..core import interview as iv
from ..core import qr as qr_mod
from ..core.audit import tally, verdict
from ..core.errors import TesseraError
from ..core.manager import Session, quick_target
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
    target = quick_target(getattr(args, "target", "") or "")
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
    session = Session.connect(target, sudo_password=password,
                              resolve_public_ip=not getattr(args, "offline", False))
    if session.can_root:
        ui.ok("{}  -  {}".format(session.facts.summary(),
                                 summary_line(session.state)))
    else:
        ui.ok(session.facts.summary())
        ui.warn("No root on this target: {}".format(session.state_error))
        ui.note("Read-only commands still work. To make changes, re-run with "
                "--ask-sudo-password or connect as root.")
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
        for p in info.get("peers", []):
            if name == "wireguard":
                rows.append([p.get("public_key", "")[:16] + "...",
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
        headers = {"wireguard": ["Key", "Allowed IPs", "Handshake", "Rx / Tx"],
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
            ui.table(["Name", "Address", "Created", "State"],
                     [[p.name, p.address_v4 or p.fingerprint[:23] or "-",
                       p.created[:10], "revoked" if p.revoked else "active"]
                      for p in peers])
        return EXIT_OK

    if args.action == "add":
        peer, config = session.add_peer(engine, args.name)
        ui.ok("Added '{}' to {}".format(args.name, engine))
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
                        help="user@host[:port], or omit for this machine")
        sp.add_argument("--user", default="", help="SSH user")
        sp.add_argument("--port", type=int, default=0, help="SSH port")
        sp.add_argument("-i", "--identity", default="", help="SSH key file")
        sp.add_argument("--ask-sudo-password", action="store_true",
                        help="prompt for the remote sudo password")
        sp.add_argument("--offline", action="store_true",
                        help="skip public IP lookup")

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

"""Does the server still look like the inventory says it does?

Tessera's inventory is the basis for adding peers, rendering configs and - most
consequentially - deciding what the uninstaller is allowed to delete. All of
that assumes the file still describes reality.

It might not. Someone edits ``wg0.conf`` by hand to add a peer in a hurry. A
config-management run reverts a sysctl. A package upgrade replaces a unit file.
An expired peer is revoked by the timer while nobody is looking. None of these
are exotic; they are a normal Tuesday.

``verify`` compares the two and reports the differences. It is read-only, and
it never repairs anything on its own: silently "fixing" a peer that a colleague
added an hour ago by deleting them is a worse outcome than saying so. The CLI
offers ``--fix`` for the cases that are unambiguous, and lists the rest.

Findings are shaped like the audit's, so both render the same way.
"""

from __future__ import annotations

import shlex
from typing import Dict, List

from .adopt import parse_wg_conf
from .models import Facts, Finding
from .state import ServerState
from .transport import Transport


def run(t: Transport, f: Facts, state: ServerState) -> List[Finding]:
    """Compare inventory against reality.  Read-only."""
    findings: List[Finding] = []
    if not state.installed_engines:
        return [Finding("info", "Nothing to verify",
                        "This server has no Tessera-managed install.")]

    findings += _check_artifacts(t, state)
    for engine in state.installed_engines:
        if engine == "wireguard":
            findings += _check_wireguard(t, state)
        elif engine == "openvpn":
            findings += _check_openvpn(t, state)
    findings += _check_services(t, f, state)
    if not any(x.is_problem for x in findings):
        findings.insert(0, Finding(
            "pass", "The server matches the inventory",
            "Every recorded file, service and peer is where it should be."))
    return findings


def _check_artifacts(t: Transport, state: ServerState) -> List[Finding]:
    """Every file we recorded should still exist."""
    missing: List[str] = []
    for artifact in state.all_artifacts():
        if artifact.kind not in ("file", "dir"):
            continue
        if artifact.pre_existing and not artifact.adopted:
            continue
        if not t.file_exists(artifact.ref):
            missing.append(artifact.ref)
    if not missing:
        return []
    return [Finding(
        "warn", "{} recorded file{} missing".format(
            len(missing), " is" if len(missing) == 1 else "s are"),
        "\n".join(missing),
        "Something removed these outside Tessera. If the VPN still works they "
        "may be harmless leftovers in the inventory; if it does not, restore "
        "from a backup.", weight=2)]


def _check_wireguard(t: Transport, state: ServerState) -> List[Finding]:
    out: List[Finding] = []
    rec = state.engine("wireguard")
    if rec is None:
        return out
    iface = (rec.config or {}).get("interface", "wg0")
    conf_path = "/etc/wireguard/{}.conf".format(iface)
    if not t.file_exists(conf_path):
        return [Finding("fail", "WireGuard config is gone",
                        "{} does not exist.".format(conf_path),
                        "Restore from a backup, or reinstall.",
                        engine="wireguard", weight=3)]

    body = t.run_root("cat {}".format(shlex.quote(conf_path))).stdout
    on_disk = parse_wg_conf(body)
    disk_keys = {p["public_key"] for p in on_disk["peers"] if p["public_key"]}
    known = {p.get("public_key") for p in rec.peers
             if p.get("public_key") and not p.get("revoked")}

    unknown = disk_keys - known
    absent = known - disk_keys
    if unknown:
        names = []
        for p in on_disk["peers"]:
            if p["public_key"] in unknown:
                names.append(p.get("name") or p["public_key"][:16] + "...")
        out.append(Finding(
            "warn", "{} peer{} on the server that Tessera does not know about"
            .format(len(unknown), "" if len(unknown) == 1 else "s"),
            "\n".join(names),
            "Someone added these by editing the config directly. They have "
            "working access. Run 'tessera verify --fix' to import them into "
            "the inventory, or remove them from the config by hand.",
            engine="wireguard", weight=2))
    if absent:
        names = [p.get("name", "?") for p in rec.peers
                 if p.get("public_key") in absent]
        out.append(Finding(
            "warn", "{} peer{} in the inventory but not on the server".format(
                len(absent), "" if len(absent) == 1 else "s"),
            "\n".join(names),
            "These cannot connect. Most often the expiry timer revoked them, "
            "in which case 'tessera verify --fix' will reconcile the record.",
            engine="wireguard", weight=2))

    live = t.run_root("wg show {} dump 2>/dev/null".format(shlex.quote(iface)))
    if live.ok and live.stdout.strip():
        running = {l.split("\t")[0] for l in live.stdout.splitlines()[1:]
                   if l.strip()}
        stale = disk_keys - running
        if stale:
            out.append(Finding(
                "info", "{} peer{} in the config but not loaded".format(
                    len(stale), "" if len(stale) == 1 else "s"),
                "", "The file was edited without reloading. "
                    "'wg syncconf {i} <(wg-quick strip {i})' applies it "
                    "without dropping anyone.".format(i=iface),
                engine="wireguard"))

    recorded_port = (rec.config or {}).get("port")
    if recorded_port and on_disk["port"] and on_disk["port"] != recorded_port:
        out.append(Finding(
            "warn", "WireGuard port has changed",
            "Inventory says {}, the config says {}.".format(
                recorded_port, on_disk["port"]),
            "Client configs generated from the inventory will point at the "
            "wrong port.", engine="wireguard", weight=2))
    return out


def _check_openvpn(t: Transport, state: ServerState) -> List[Finding]:
    out: List[Finding] = []
    rec = state.engine("openvpn")
    if rec is None:
        return out
    index = "/etc/openvpn/server/easy-rsa/pki/index.txt"
    if not t.file_exists(index):
        return [Finding("warn", "OpenVPN PKI not found",
                        "{} is missing.".format(index),
                        "Certificates cannot be issued or revoked.",
                        engine="openvpn", weight=2)]
    from .adopt import _parse_index
    on_disk = _parse_index(t.run_root("cat {}".format(shlex.quote(index))).stdout)
    disk_active = {p["name"] for p in on_disk if not p["revoked"]}
    known_active = {p.get("name") for p in rec.peers if not p.get("revoked")}

    unknown = disk_active - known_active
    if unknown:
        out.append(Finding(
            "warn", "{} certificate{} the inventory does not list".format(
                len(unknown), "" if len(unknown) == 1 else "s"),
            "\n".join(sorted(unknown)),
            "Issued outside Tessera. 'tessera verify --fix' imports them.",
            engine="openvpn", weight=2))
    revoked_on_disk = {p["name"] for p in on_disk if p["revoked"]}
    wrongly_active = revoked_on_disk & known_active
    if wrongly_active:
        out.append(Finding(
            "info", "{} revoked certificate{} still listed as active".format(
                len(wrongly_active), "" if len(wrongly_active) == 1 else "s"),
            "\n".join(sorted(wrongly_active)),
            "The CA has revoked these; the inventory has not caught up. "
            "'tessera verify --fix' reconciles it.", engine="openvpn"))
    return out


def _check_services(t: Transport, f: Facts, state: ServerState) -> List[Finding]:
    out: List[Finding] = []
    for artifact in state.all_artifacts():
        if artifact.kind != "service":
            continue
        unit = artifact.ref
        if f.init == "systemd":
            active = t.run("systemctl is-active --quiet {}".format(
                shlex.quote(unit))).ok
        else:
            active = t.run("rc-service {} status >/dev/null 2>&1".format(
                shlex.quote(unit))).ok
        if unit.endswith(".timer") or unit.startswith("tessera-"):
            continue
        if not active:
            out.append(Finding(
                "fail", "{} is not running".format(unit),
                "", "Nobody can connect. Check "
                    "'systemctl status {}'.".format(unit),
                engine=artifact.engine, weight=3))
    return out


# --------------------------------------------------------------------------- #
# Repair
# --------------------------------------------------------------------------- #
def fixable(t: Transport, state: ServerState) -> Dict[str, List[str]]:
    """What ``--fix`` would change, described before it does it."""
    plan: Dict[str, List[str]] = {"import": [], "revoke": [], "forget": []}
    rec = state.engine("wireguard")
    if rec:
        iface = (rec.config or {}).get("interface", "wg0")
        conf = "/etc/wireguard/{}.conf".format(iface)
        if t.file_exists(conf):
            on_disk = parse_wg_conf(
                t.run_root("cat {}".format(shlex.quote(conf))).stdout)
            disk = {p["public_key"]: p for p in on_disk["peers"]
                    if p["public_key"]}
            known = {p.get("public_key") for p in rec.peers
                     if not p.get("revoked")}
            for key, p in disk.items():
                if key not in known:
                    plan["import"].append(
                        "wireguard:{}".format(p.get("name") or key[:16]))
            for p in rec.peers:
                if not p.get("revoked") and p.get("public_key") not in disk:
                    plan["forget"].append("wireguard:{}".format(p.get("name")))
    return plan


def apply_fix(t: Transport, state: ServerState) -> List[str]:
    """Reconcile the inventory to what the server actually has.

    Only ever edits the inventory, never the server. Importing an unknown peer
    records access that already exists; it does not grant anything new. That
    asymmetry is deliberate - a repair tool that can hand out access is a
    repair tool nobody should run unattended.
    """
    from .models import Peer, utcnow
    from dataclasses import asdict
    changed: List[str] = []

    rec = state.engine("wireguard")
    if rec is None:
        return changed
    iface = (rec.config or {}).get("interface", "wg0")
    conf = "/etc/wireguard/{}.conf".format(iface)
    if not t.file_exists(conf):
        return changed
    on_disk = parse_wg_conf(t.run_root("cat {}".format(shlex.quote(conf))).stdout)
    disk = {p["public_key"]: p for p in on_disk["peers"] if p["public_key"]}
    known = {p.get("public_key") for p in rec.peers if not p.get("revoked")}

    for key, raw in disk.items():
        if key in known:
            continue
        v4 = v6 = ""
        for cidr in raw.get("allowed_ips", []):
            addr = cidr.split("/")[0]
            if ":" in addr and not v6:
                v6 = addr
            elif "." in addr and not v4:
                v4 = addr
        peer = Peer(name=raw.get("name") or "imported-{}".format(key[:8]),
                    engine="wireguard", public_key=key,
                    preshared_key=raw.get("preshared_key", ""),
                    address_v4=v4, address_v6=v6, interface=iface,
                    note="imported by verify --fix on {}".format(utcnow()[:10]))
        stored = asdict(peer)
        stored["private_key"] = ""
        rec.peers.append(stored)
        changed.append("imported {}".format(peer.name))

    for stored in rec.peers:
        if not stored.get("revoked") and stored.get("public_key") not in disk:
            stored["revoked"] = True
            stored["note"] = "not present on the server at last verify"
            changed.append("marked {} revoked".format(stored.get("name")))

    if changed:
        state.set_engine(rec)
    return changed

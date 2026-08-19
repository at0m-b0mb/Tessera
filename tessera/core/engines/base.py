"""The interface every engine implements, plus the OS-shaped helpers.

Everything distro-specific lives here rather than being scattered through the
three engines.  ``pkg_install`` knows that Debian needs a non-interactive
frontend and that Alpine wants ``apk add``; the WireGuard engine just asks for
a package by name.  That is why adding a fourth engine later is small.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..models import Facts, InstallSpec, Peer
from ..plan import Plan, Step, StepKind
from ..state import Artifact, ServerState
from ..transport import Transport


@dataclass
class EngineContext:
    """Everything an engine needs to build a plan."""

    transport: Transport
    facts: Facts
    spec: InstallSpec
    state: ServerState
    #: Filled in as the plan is built, recorded into state on success.
    artifacts: List[Artifact] = field(default_factory=list)

    def note(self, kind: str, ref: str, engine: str = "",
             pre_existing: bool = False, backup: str = "", note: str = "") -> None:
        self.artifacts.append(Artifact(
            kind=kind, ref=ref, engine=engine,
            pre_existing=pre_existing, backup=backup, note=note))


class Engine:
    """Base class.  Subclasses fill in the plan builders."""

    name: str = ""
    label: str = ""
    blurb: str = ""
    #: What this engine is genuinely best at, shown in the chooser.
    strengths: Tuple[str, ...] = ()
    tradeoffs: Tuple[str, ...] = ()

    # -- planning --------------------------------------------------------------
    def plan_install(self, ctx: EngineContext) -> Plan:
        raise NotImplementedError

    def plan_uninstall(self, ctx: EngineContext, purge: bool = True) -> Plan:
        raise NotImplementedError

    def plan_add_peer(self, ctx: EngineContext, name: str,
                      **options) -> Tuple[Plan, Peer, str]:
        """Return (plan, peer, client_config_text)."""
        raise NotImplementedError

    def plan_remove_peer(self, ctx: EngineContext, name: str) -> Plan:
        raise NotImplementedError

    # -- runtime ---------------------------------------------------------------
    def status(self, ctx: EngineContext) -> Dict[str, object]:
        return {}

    def audit(self, ctx: EngineContext) -> List:
        return []


# --------------------------------------------------------------------------- #
# Package management
# --------------------------------------------------------------------------- #
def pkg_refresh(f: Facts) -> str:
    return {
        "apt": "DEBIAN_FRONTEND=noninteractive apt-get update -qq",
        "dnf": "dnf -q makecache",
        "yum": "yum -q makecache",
        "pacman": "pacman -Sy --noconfirm",
        "apk": "apk update -q",
        "zypper": "zypper --non-interactive --quiet refresh",
    }.get(f.pkg, "true")


def pkg_install(f: Facts, packages: List[str]) -> str:
    joined = " ".join(shlex.quote(p) for p in packages)
    return {
        "apt": "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
               "-o Dpkg::Options::=--force-confdef "
               "-o Dpkg::Options::=--force-confold " + joined,
        "dnf": "dnf install -y -q " + joined,
        "yum": "yum install -y -q " + joined,
        "pacman": "pacman -S --needed --noconfirm " + joined,
        "apk": "apk add --no-cache " + joined,
        "zypper": "zypper --non-interactive install " + joined,
    }.get(f.pkg, "false")


def pkg_remove(f: Facts, packages: List[str]) -> str:
    """Remove packages, and never let removal cascade.

    ``--no-autoremove`` / ``--noautoremove`` matter here.  Without them, apt
    happily removes the dependencies it pulled in, and on a box where something
    else started depending on one of them in the meantime you have just broken
    an unrelated service during what the user thought was a VPN uninstall.
    """
    joined = " ".join(shlex.quote(p) for p in packages)
    return {
        "apt": "DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq "
               "--no-autoremove " + joined,
        "dnf": "dnf remove -y -q --noautoremove " + joined,
        "yum": "yum remove -y -q --noautoremove " + joined,
        "pacman": "pacman -R --noconfirm " + joined,
        "apk": "apk del " + joined,
        "zypper": "zypper --non-interactive remove " + joined,
    }.get(f.pkg, "false")


def pkg_installed(f: Facts, package: str) -> str:
    """A command that exits 0 when the package is already present."""
    p = shlex.quote(package)
    return {
        "apt": "dpkg-query -W -f='${{Status}}' {} 2>/dev/null "
               "| grep -q 'ok installed'".format(p),
        "dnf": "rpm -q {} >/dev/null 2>&1".format(p),
        "yum": "rpm -q {} >/dev/null 2>&1".format(p),
        "pacman": "pacman -Qi {} >/dev/null 2>&1".format(p),
        "apk": "apk info -e {} >/dev/null 2>&1".format(p),
        "zypper": "rpm -q {} >/dev/null 2>&1".format(p),
    }.get(f.pkg, "false")


def already_installed(t: Transport, f: Facts, package: str) -> bool:
    return t.run(pkg_installed(f, package)).ok


# --------------------------------------------------------------------------- #
# Services
# --------------------------------------------------------------------------- #
def svc_enable_start(f: Facts, unit: str) -> str:
    if f.init == "openrc":
        return "rc-update add {u} default && rc-service {u} restart".format(
            u=shlex.quote(unit))
    return "systemctl enable --now {}".format(shlex.quote(unit))


def svc_restart(f: Facts, unit: str) -> str:
    if f.init == "openrc":
        return "rc-service {} restart".format(shlex.quote(unit))
    return "systemctl restart {}".format(shlex.quote(unit))


def svc_stop_disable(f: Facts, unit: str) -> str:
    if f.init == "openrc":
        return ("rc-service {u} stop 2>/dev/null; "
                "rc-update del {u} 2>/dev/null; true".format(u=shlex.quote(unit)))
    return ("systemctl disable --now {u} 2>/dev/null; true".format(
        u=shlex.quote(unit)))


def svc_is_active(f: Facts, unit: str) -> str:
    if f.init == "openrc":
        return "rc-service {} status >/dev/null 2>&1".format(shlex.quote(unit))
    return "systemctl is-active --quiet {}".format(shlex.quote(unit))


# --------------------------------------------------------------------------- #
# sysctl
# --------------------------------------------------------------------------- #
def sysctl_step(key: str, value: str, f: Facts, filename: str) -> Step:
    return Step(
        id="sysctl-{}".format(key.replace(".", "-")),
        title="Set {} = {}".format(key, value),
        kind=StepKind.CONFIG,
        command=("mkdir -p /etc/sysctl.d && printf '%s = %s\\n' {k} {v} "
                 ">> {f} && sysctl -w {k}={v} >/dev/null").format(
                     k=shlex.quote(key), v=shlex.quote(value),
                     f=shlex.quote(filename)),
        undo="rm -f {}".format(shlex.quote(filename)),
        why="Kernel setting required for traffic to be routed between "
            "interfaces.")


def sysctl_current(t: Transport, key: str) -> str:
    return t.run("sysctl -n {} 2>/dev/null".format(shlex.quote(key))).out


# --------------------------------------------------------------------------- #
# Firewall
# --------------------------------------------------------------------------- #
def open_port_cmd(f: Facts, port: int, proto: str = "udp") -> str:
    """Open an inbound port using whatever firewall actually runs here."""
    if f.firewall == "firewalld":
        return ("firewall-cmd --permanent --add-port={p}/{pr} && "
                "firewall-cmd --reload").format(p=port, pr=proto)
    if f.firewall == "ufw":
        return "ufw allow {p}/{pr}".format(p=port, pr=proto)
    if f.firewall == "nftables":
        return ("nft add rule inet filter input {pr} dport {p} accept "
                "2>/dev/null || true").format(p=port, pr=proto)
    return ("iptables -C INPUT -p {pr} --dport {p} -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p {pr} --dport {p} -j ACCEPT").format(
                p=port, pr=proto)


def close_port_cmd(f: Facts, port: int, proto: str = "udp") -> str:
    if f.firewall == "firewalld":
        return ("firewall-cmd --permanent --remove-port={p}/{pr} 2>/dev/null; "
                "firewall-cmd --reload 2>/dev/null; true").format(p=port, pr=proto)
    if f.firewall == "ufw":
        return "ufw delete allow {p}/{pr} 2>/dev/null; true".format(p=port, pr=proto)
    if f.firewall == "nftables":
        return "true"
    return ("iptables -D INPUT -p {pr} --dport {p} -j ACCEPT 2>/dev/null; "
            "true").format(p=port, pr=proto)


def masquerade_rules(nic: str, subnet: str, v6: bool = False) -> Tuple[str, str]:
    """Return (add, remove) NAT commands for one subnet.

    ``-C`` first so re-running an install is idempotent instead of stacking a
    second identical rule every time, which is a real failure mode of the
    reference scripts when you run them twice.
    """
    cmd = "ip6tables" if v6 else "iptables"
    spec = "-t nat POSTROUTING -s {s} -o {n} -j MASQUERADE".format(
        s=shlex.quote(subnet), n=shlex.quote(nic))
    add = "{c} -C {spec} 2>/dev/null || {c} -A {spec}".format(c=cmd, spec=spec)
    rem = "{c} -D {spec} 2>/dev/null; true".format(c=cmd, spec=spec)
    return add, rem

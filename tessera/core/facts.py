"""Learn everything about the target before touching it.

This is deliberately one round trip.  A naive implementation runs twenty small
commands, and over a 200 ms link that is four seconds of the user watching a
spinner.  Instead we send a single read-only bash script that prints
``key=value`` lines, and parse the result.  Nothing here writes, installs, or
changes anything - you can safely run detection against a production box.

The detection also drives *refusals*.  WireGuard needs a kernel module, so an
OpenVZ container simply cannot run it, and it is much kinder to say so before
we install packages than after.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .errors import UnsupportedTargetError
from .models import Facts
from .transport import Transport

PKG_FOR_FAMILY = {
    "debian": "apt", "rhel": "dnf", "arch": "pacman",
    "alpine": "apk", "suse": "zypper",
}

FAMILY_FOR_ID = {
    "debian": "debian", "ubuntu": "debian", "raspbian": "debian",
    "linuxmint": "debian", "pop": "debian", "devuan": "debian",
    "kali": "debian", "parrot": "debian",
    "fedora": "rhel", "centos": "rhel", "rhel": "rhel", "rocky": "rhel",
    "almalinux": "rhel", "ol": "rhel", "oracle": "rhel", "amzn": "rhel",
    "arch": "arch", "manjaro": "arch", "endeavouros": "arch",
    "alpine": "alpine",
    "opensuse": "suse", "opensuse-leap": "suse", "opensuse-tumbleweed": "suse",
    "sles": "suse",
}

# Minimum releases that can actually run a modern stack.
MIN_VERSION = {
    "debian": 10, "ubuntu": 20, "fedora": 32, "centos": 8,
    "rocky": 8, "almalinux": 8, "rhel": 8,
}

_PROBE = r"""
set -u
emit() { printf '%s=%s\n' "$1" "$2"; }

if [ -r /etc/os-release ]; then
  . /etc/os-release
  emit os_id "${ID:-}"
  emit os_name "${PRETTY_NAME:-${NAME:-}}"
  emit version_id "${VERSION_ID:-}"
  emit version_codename "${VERSION_CODENAME:-}"
  emit id_like "${ID_LIKE:-}"
fi

emit kernel "$(uname -r 2>/dev/null || echo)"
emit arch "$(uname -m 2>/dev/null || echo)"
emit uid "$(id -u 2>/dev/null || echo)"

# Virtualisation: systemd-detect-virt is the most reliable when present.
if command -v systemd-detect-virt >/dev/null 2>&1; then
  emit virt "$(systemd-detect-virt 2>/dev/null || echo none)"
elif command -v virt-what >/dev/null 2>&1; then
  emit virt "$(virt-what 2>/dev/null | head -1)"
else
  emit virt unknown
fi

# Init system decides whether we say systemctl or rc-service.
if [ -d /run/systemd/system ]; then emit init systemd
elif command -v rc-service >/dev/null 2>&1; then emit init openrc
else emit init other; fi

# TUN/TAP is required by both OpenVPN and WireGuard's userspace fallback.
if [ -e /dev/net/tun ]; then emit has_tun 1; else emit has_tun 0; fi

# Default-route interface: the one we MASQUERADE out of.
emit nic "$(ip -4 route show default 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
emit nic6 "$(ip -6 route show default 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"

# Addresses actually bound to this host.
emit local_v4 "$(ip -4 addr show scope global 2>/dev/null | sed -ne 's|^.* inet \([^/]*\)/.*$|\1|p' | head -1)"
emit local_v6 "$(ip -6 addr show scope global 2>/dev/null | sed -ne 's|^.* inet6 \([^/]*\)/.*$|\1|p' | head -1)"

# Firewall in charge.  Order matters: firewalld and ufw both sit on top of
# nftables/iptables, so ask about the manager before the mechanism.
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then emit firewall firewalld
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then emit firewall ufw
elif command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then emit firewall nftables
elif command -v iptables >/dev/null 2>&1; then emit firewall iptables
else emit firewall none; fi

if command -v getenforce >/dev/null 2>&1; then emit selinux "$(getenforce 2>/dev/null)"; else emit selinux Disabled; fi

# IPv6 usable at all?
if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = "0" ]; then emit ipv6 1; else emit ipv6 0; fi
emit ip_forward "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"

# What is already installed, and at what version.
if command -v wg >/dev/null 2>&1; then emit wireguard "$(wg --version 2>/dev/null | awk '{print $2}')"; fi
if command -v openvpn >/dev/null 2>&1; then emit openvpn "$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')"; fi
if command -v tailscale >/dev/null 2>&1; then emit tailscale "$(tailscale version 2>/dev/null | head -1)"; fi

# Existing Tessera-managed installs.
if [ -f /etc/tessera/state.json ]; then emit tessera_state 1; else emit tessera_state 0; fi

# Ports already listening, so we can refuse to collide.
emit listening "$(( ss -tulnH 2>/dev/null || netstat -tuln 2>/dev/null ) | awk '{print $5}' | sed 's/.*://' | sort -un | tr '\n' ',')"
"""

# Resolvers used to learn the public IP when the box is behind NAT.  Several,
# because any one of them can be down or blocked, and we compare answers.
_IP_LOOKUPS = [
    "curl -fsS --max-time 6 https://api.ipify.org",
    "curl -fsS --max-time 6 https://ifconfig.co",
    "dig -4 +short myip.opendns.com @resolver1.opendns.com",
]


def gather(t: Transport, *, resolve_public_ip: bool = True) -> Facts:
    """Run the probe and build a Facts object.  Read-only."""
    res = t.run(_PROBE, timeout=90)
    if not res.ok and not res.stdout:
        raise UnsupportedTargetError(
            "could not inspect the target",
            (res.stderr or "").strip() or "Is this a Linux machine?")

    kv = _parse_kv(res.stdout)
    f = Facts()
    f.os_id = kv.get("os_id", "").lower()
    f.os_name = kv.get("os_name", "")
    f.version_id = kv.get("version_id", "")
    f.version_codename = kv.get("version_codename", "")
    f.kernel = kv.get("kernel", "")
    f.arch = kv.get("arch", "")
    f.virt = kv.get("virt", "") if kv.get("virt") != "none" else ""
    f.init = kv.get("init", "")
    f.has_tun = kv.get("has_tun") == "1"
    f.has_ipv6 = kv.get("ipv6") == "1"
    f.nic = kv.get("nic") or kv.get("nic6", "")
    f.private_ipv4 = kv.get("local_v4", "")
    f.firewall = kv.get("firewall", "none")
    f.selinux = kv.get("selinux", "").lower() == "enforcing"

    f.family = FAMILY_FOR_ID.get(f.os_id, "")
    if not f.family:
        for like in (kv.get("id_like", "") or "").split():
            if like.lower() in FAMILY_FOR_ID:
                f.family = FAMILY_FOR_ID[like.lower()]
                break
    f.pkg = PKG_FOR_FAMILY.get(f.family, "")
    if f.family == "rhel" and f.os_id in ("centos", "rhel", "ol", "oracle"):
        # dnf exists on 8+, yum below that.  Ask rather than guess.
        if t.which("dnf") is None:
            f.pkg = "yum"

    for engine in ("wireguard", "openvpn", "tailscale"):
        if kv.get(engine):
            f.installed[engine] = kv[engine]

    if resolve_public_ip:
        f.public_ipv4 = _public_ip(t)
        if f.has_ipv6:
            f.public_ipv6 = kv.get("local_v6", "")
    if f.public_ipv4 and f.private_ipv4:
        f.behind_nat = f.public_ipv4 != f.private_ipv4

    return f


def listening_ports(t: Transport) -> List[int]:
    res = t.run("( ss -tulnH 2>/dev/null || netstat -tuln 2>/dev/null ) "
                "| awk '{print $5}' | sed 's/.*://' | sort -un")
    out = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            out.append(int(line))
    return out


def _public_ip(t: Transport) -> str:
    """Ask two independent services and only trust an answer they agree on."""
    answers: List[str] = []
    for cmd in _IP_LOOKUPS:
        r = t.run(cmd, timeout=12)
        v = r.out.strip().strip('"')
        if _is_ipv4(v):
            answers.append(v)
            if answers.count(v) >= 2:
                return v
    return answers[0] if answers else ""


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255
                                    for p in parts))


def _parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------------------- #
# Compatibility
# --------------------------------------------------------------------------- #
def check_support(f: Facts, engines: List[str]) -> List[Tuple[str, str, str]]:
    """Return blocking problems as (severity, engine, message).

    severity is "block" (cannot proceed) or "warn" (proceed with caution).
    """
    issues: List[Tuple[str, str, str]] = []

    if not f.family:
        issues.append(("block", "", (
            "unrecognised distribution '{}'. Tessera supports Debian/Ubuntu, "
            "RHEL/Fedora/Rocky/Alma, Arch, Alpine and openSUSE."
            .format(f.os_id or "unknown"))))
        return issues

    major = _major(f.version_id)
    floor = MIN_VERSION.get(f.os_id)
    if floor and major and major < floor:
        issues.append(("block", "", (
            "{} {} is too old; {} {} or newer is required"
            .format(f.os_name or f.os_id, f.version_id, f.os_id, floor))))

    if f.virt == "openvz":
        issues.append(("block", "", (
            "OpenVZ containers share the host kernel and cannot load the "
            "WireGuard module or create TUN devices.")))

    if "wireguard" in engines:
        if f.virt == "lxc":
            issues.append(("warn", "wireguard", (
                "LXC shares the host kernel: WireGuard works only if the "
                "module is loaded on the host and the container is allowed "
                "/dev/net/tun.")))
        if _kernel_older_than(f.kernel, (5, 6)) and f.virt:
            issues.append(("warn", "wireguard", (
                "kernel {} predates in-tree WireGuard (5.6); a DKMS module "
                "will be built, which needs headers.".format(f.kernel))))

    if "openvpn" in engines and not f.has_tun:
        issues.append(("block", "openvpn", (
            "/dev/net/tun is missing. OpenVPN cannot create a tunnel without "
            "it. On a VPS, ask your provider to enable TUN/TAP.")))

    if "tailscale" in engines and not f.has_tun:
        issues.append(("warn", "tailscale", (
            "/dev/net/tun is missing; Tailscale will fall back to userspace "
            "networking, which is slower and cannot act as an exit node.")))

    if f.init not in ("systemd", "openrc"):
        issues.append(("warn", "", (
            "no recognised init system; services will not start at boot "
            "automatically and must be managed by hand.")))

    return issues


def _major(version: str) -> Optional[int]:
    m = re.match(r"(\d+)", version or "")
    return int(m.group(1)) if m else None


def _kernel_older_than(kernel: str, minimum: Tuple[int, int]) -> bool:
    m = re.match(r"(\d+)\.(\d+)", kernel or "")
    if not m:
        return False
    return (int(m.group(1)), int(m.group(2))) < minimum

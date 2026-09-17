"""The domain objects Tessera passes around.

These are plain dataclasses with no Qt, no I/O and no shell.  The GUI, the CLI
and the tests all speak this vocabulary, which is why neither front end has to
know anything about the other.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List

ENGINES = ("wireguard", "openvpn", "tailscale")


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- #
# Target
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """Where we are installing.  ``host`` of "" or "localhost" means locally."""

    host: str = "localhost"
    user: str = ""
    port: int = 22
    identity: str = ""
    label: str = ""

    @property
    def is_local(self) -> bool:
        return self.host in ("", "localhost", "127.0.0.1", "::1")

    def display(self) -> str:
        if self.label:
            return self.label
        if self.is_local:
            return "this machine"
        return "{}{}".format((self.user + "@") if self.user else "", self.host)


@dataclass
class Facts:
    """What we learned about the target before touching it."""

    os_id: str = ""              # debian, ubuntu, fedora, arch, alpine...
    os_name: str = ""            # pretty name
    version_id: str = ""
    version_codename: str = ""
    family: str = ""             # debian | rhel | arch | alpine | suse
    pkg: str = ""                # apt | dnf | yum | pacman | apk | zypper
    kernel: str = ""
    arch: str = ""
    virt: str = ""               # kvm, lxc, openvz, none...
    init: str = ""               # systemd | openrc | other
    public_ipv4: str = ""
    public_ipv6: str = ""
    private_ipv4: str = ""
    nic: str = ""                # default-route interface
    has_tun: bool = False
    has_ipv6: bool = False
    firewall: str = ""           # firewalld | ufw | nftables | iptables | none
    selinux: bool = False
    behind_nat: bool = False
    installed: Dict[str, str] = field(default_factory=dict)  # engine -> version

    def summary(self) -> str:
        return "{} {} ({}, {}, {})".format(
            self.os_name or self.os_id, self.version_id,
            self.arch, self.init or "?", self.virt or "bare metal")


# --------------------------------------------------------------------------- #
# Peers
# --------------------------------------------------------------------------- #
@dataclass
class Peer:
    """A client device.  One record covers all three engines."""

    name: str
    engine: str
    created: str = field(default_factory=utcnow)
    # WireGuard
    public_key: str = ""
    preshared_key: str = ""
    private_key: str = ""        # kept client-side only; never sent to server
    address_v4: str = ""
    address_v6: str = ""
    # OpenVPN
    cert_serial: str = ""
    fingerprint: str = ""
    expires: str = ""
    # Common
    #: Which interface this peer lives on, so the expiry script knows where
    #: to look without having to parse the inventory.
    interface: str = ""
    #: ISO date after which access is revoked automatically. Empty = permanent.
    access_expires: str = ""
    revoked: bool = False
    note: str = ""
    last_handshake: str = ""
    rx_bytes: int = 0
    tx_bytes: int = 0

    def redacted(self) -> "Peer":
        """Copy with secrets stripped, for logs and exports."""
        c = Peer(**asdict(self))
        c.private_key = "<redacted>" if self.private_key else ""
        c.preshared_key = "<redacted>" if self.preshared_key else ""
        return c


# --------------------------------------------------------------------------- #
# Server configuration answers
# --------------------------------------------------------------------------- #
@dataclass
class WireGuardConfig:
    interface: str = "wg0"
    port: int = 51820
    subnet_v4: str = "10.66.66.0/24"
    subnet_v6: str = "fd42:42:42::/64"
    endpoint: str = ""
    dns: List[str] = field(default_factory=lambda: ["9.9.9.9", "149.112.112.112"])
    allowed_ips: str = "0.0.0.0/0,::/0"
    mtu: int = 0                 # 0 = let the kernel decide
    keepalive: int = 25
    enable_ipv6: bool = True
    client_to_client: bool = False


@dataclass
class OpenVPNConfig:
    port: int = 1194
    protocol: str = "udp"        # udp | tcp
    subnet_v4: str = "10.8.0.0/24"
    subnet_v6: str = "fd42:42:43::/112"
    endpoint: str = ""
    dns: List[str] = field(default_factory=lambda: ["9.9.9.9", "149.112.112.112"])
    cipher: str = "AES-256-GCM"
    auth_digest: str = "SHA256"
    cert_type: str = "ecdsa"     # ecdsa | rsa
    cert_curve: str = "prime256v1"
    rsa_bits: int = 3072
    tls_sig: str = "crypt-v2"    # crypt-v2 | crypt | auth
    tls_min: str = "1.2"
    enable_ipv6: bool = True
    client_to_client: bool = False
    compression: bool = False    # off by default: VORACLE
    duplicate_cn: bool = False
    cert_days: int = 3650
    client_cert_days: int = 825


@dataclass
class TailscaleConfig:
    auth_key: str = ""           # never persisted to disk
    hostname: str = ""
    advertise_exit_node: bool = False
    advertise_routes: List[str] = field(default_factory=list)
    accept_routes: bool = True
    accept_dns: bool = True
    ssh: bool = False
    shields_up: bool = False
    login_server: str = ""       # for Headscale
    unattended: bool = True


@dataclass
class HardeningConfig:
    """Server-level hardening applied alongside whichever engine you chose."""

    ip_forward: bool = True
    firewall: bool = True
    fail2ban: bool = False
    unattended_upgrades: bool = False
    disable_ssh_password_auth: bool = False
    sysctl_hardening: bool = True
    block_rfc1918_from_vpn: bool = True   # stop clients reaching your LAN
    kill_switch_hint: bool = True


@dataclass
class InstallSpec:
    """Everything the interview collected.  This is what a plan is built from."""

    target: Target = field(default_factory=Target)
    engines: List[str] = field(default_factory=list)
    wireguard: WireGuardConfig = field(default_factory=WireGuardConfig)
    openvpn: OpenVPNConfig = field(default_factory=OpenVPNConfig)
    tailscale: TailscaleConfig = field(default_factory=TailscaleConfig)
    hardening: HardeningConfig = field(default_factory=HardeningConfig)
    first_peer: str = "laptop"
    profile: str = "balanced"    # quick | balanced | paranoid | custom
    #: Question keys the user (or a CLI flag) set explicitly.  Filling in
    #: defaults must never overwrite these - that bug silently discards
    #: "--engine openvpn" and is invisible until someone checks the server.
    answered: List[str] = field(default_factory=list)

    def to_json(self, redact: bool = True) -> str:
        d = asdict(self)
        d.pop("answered", None)
        if redact and d.get("tailscale", {}).get("auth_key"):
            d["tailscale"]["auth_key"] = "<redacted>"
        return json.dumps(d, indent=2, sort_keys=True)


# --------------------------------------------------------------------------- #
# Findings (audit)
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """One audit observation.  ``level`` is pass | warn | fail | info."""

    level: str
    title: str
    detail: str = ""
    remedy: str = ""
    engine: str = ""
    weight: int = 1

    @property
    def is_problem(self) -> bool:
        return self.level in ("warn", "fail")

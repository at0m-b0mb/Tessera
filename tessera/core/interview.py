"""The questions, defined once.

The CLI and the GUI ask the same things in the same order with the same
defaults and the same validation, because both read this file.  If they each
had their own copy of the questions they would drift within a month, and the
GUI would quietly grow an option the CLI cannot express.

Three design rules here:

**Every question has a defensible default.**  Pressing Enter through the whole
interview must produce a genuinely secure server, not a starting point.  If a
question has no safe default it is not a question, it is a decision the tool
should be making.

**Every question carries a ``why``.**  Not a restatement of the prompt - the
actual consequence of choosing wrongly.  A person who does not know what
``AllowedIPs`` means cannot answer "what should AllowedIPs be", but they can
absolutely answer "should all your traffic go through this server, or only
traffic to the server's own network".

**Defaults are computed from the target.**  The port, the endpoint, the NIC and
the subnet come from what we detected, so the prefilled answers are already
right for this specific server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple

from . import netcalc
from .errors import ValidationError
from .keys import random_port
from .models import (Facts, InstallSpec)

# A validator returns (ok, message).  Message is shown even when ok, so it can
# carry a warning that does not block.
Validator = Callable[[Any, InstallSpec, Facts], Tuple[bool, str]]


@dataclass
class Question:
    key: str                      # dotted path into InstallSpec
    prompt: str
    kind: str = "text"            # text | int | bool | choice | multi | secret
    default: Any = None           # value, or fn(spec, facts) -> value
    choices: List[Tuple[str, str]] = field(default_factory=list)  # (value, label)
    why: str = ""
    placeholder: str = ""
    validator: Optional[Validator] = None
    #: Only asked when this returns True.
    when: Optional[Callable[[InstallSpec, Facts], bool]] = None
    #: Advanced questions are hidden behind "show advanced" in both front ends.
    advanced: bool = False
    group: str = ""

    def resolve_default(self, spec: InstallSpec, facts: Facts) -> Any:
        if callable(self.default):
            return self.default(spec, facts)
        return self.default

    def applies(self, spec: InstallSpec, facts: Facts) -> bool:
        return self.when is None or self.when(spec, facts)

    def validate(self, value: Any, spec: InstallSpec,
                 facts: Facts) -> Tuple[bool, str]:
        if self.validator is None:
            return True, ""
        return self.validator(value, spec, facts)


# --------------------------------------------------------------------------- #
# Profiles
# --------------------------------------------------------------------------- #
PROFILES = {
    "quick": {
        "label": "Quick",
        "summary": "Sensible defaults, three questions, done in a minute.",
        "detail": "WireGuard on a random high port, Quad9 DNS, all traffic "
                  "routed, kernel hardening on. This is a good server.",
    },
    "balanced": {
        "label": "Balanced",
        "summary": "The full interview, with everything pre-filled.",
        "detail": "You see and can change every meaningful setting, but you "
                  "can also press Enter through all of it.",
    },
    "paranoid": {
        "label": "Hardened",
        "summary": "Locks the server down as well as the VPN.",
        "detail": "Adds fail2ban, automatic security updates, key-only SSH, "
                  "and blocks VPN clients from reaching private networks. "
                  "Some of this can lock you out if you are careless, so each "
                  "step is confirmed.",
    },
    "custom": {
        "label": "Custom",
        "summary": "Nothing assumed.",
        "detail": "Every question asked, including the advanced ones.",
    },
}


def apply_profile(spec: InstallSpec, name: str, facts: Facts) -> InstallSpec:
    """Pre-answer the questions a profile decides on the user's behalf."""
    spec.profile = name
    h = spec.hardening
    if name == "quick":
        spec.engines = spec.engines or ["wireguard"]
        h.sysctl_hardening = True
        h.firewall = True
    elif name == "paranoid":
        h.fail2ban = True
        h.unattended_upgrades = True
        h.disable_ssh_password_auth = True
        h.sysctl_hardening = True
        h.block_rfc1918_from_vpn = True
        for key in ("hardening.fail2ban", "hardening.unattended_upgrades",
                    "hardening.disable_ssh_password_auth",
                    "hardening.sysctl_hardening",
                    "hardening.block_rfc1918_from_vpn"):
            if key not in spec.answered:
                spec.answered.append(key)
        spec.openvpn.cipher = "AES-256-GCM"
        spec.openvpn.tls_sig = "crypt-v2"
        spec.openvpn.tls_min = "1.3"
        spec.wireguard.keepalive = 25
    return spec


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #
def _v_port(value, spec, facts):
    ok, msg = netcalc.validate_port(value)
    if not ok:
        return False, msg
    return True, msg


def _v_subnet4(value, spec, facts):
    return netcalc.validate_subnet(str(value), 4)


def _v_subnet6(value, spec, facts):
    return netcalc.validate_subnet(str(value), 6)


def _v_endpoint(value, spec, facts):
    v = str(value).strip()
    if not v:
        return False, "an endpoint is required so clients know where to connect"
    if netcalc.looks_like_hostname(v):
        return True, ""
    try:
        import ipaddress
        addr = ipaddress.ip_address(v)
    except ValueError:
        return False, "not a valid IP address or hostname"
    if addr.is_private:
        return True, ("that is a private address - clients outside this "
                      "network will not be able to reach it")
    return True, ""


def _v_dns(value, spec, facts):
    entries = [e.strip() for e in str(value).replace(",", " ").split() if e.strip()]
    if not entries:
        return False, "at least one resolver is required"
    import ipaddress
    for e in entries:
        try:
            ipaddress.ip_address(e)
        except ValueError:
            return False, "'{}' is not an IP address".format(e)
    return True, ""


def _v_name(value, spec, facts):
    import re
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,30}$", str(value)):
        return False, ("use letters, digits, dash and underscore, starting "
                       "with a letter or digit")
    return True, ""


def _v_engines(value, spec, facts):
    if not value:
        return False, "choose at least one"
    return True, ""


# --------------------------------------------------------------------------- #
# The questions
# --------------------------------------------------------------------------- #
def _default_endpoint(spec, facts):
    return facts.public_ipv4 or facts.private_ipv4 or ""


def _wg(spec, facts):
    return "wireguard" in spec.engines


def _ovpn(spec, facts):
    return "openvpn" in spec.engines


def _ts(spec, facts):
    return "tailscale" in spec.engines


QUESTIONS: List[Question] = [
    Question(
        key="engines", prompt="Which VPN should this server run?",
        kind="multi", default=lambda s, f: ["wireguard"],
        choices=[
            ("wireguard", "WireGuard - fastest, simplest, best default"),
            ("openvpn", "OpenVPN - gets through restrictive networks"),
            ("tailscale", "Tailscale - mesh, no open port needed"),
        ],
        validator=_v_engines, group="What to install",
        why="You can run more than one. WireGuard for everyday use and "
            "OpenVPN on TCP 443 as a fallback is a common, sensible pairing: "
            "when a hotel network blocks UDP, the fallback still works."),

    Question(
        key="first_peer", prompt="Name for your first device",
        kind="text", default="laptop", validator=_v_name,
        when=lambda s, f: bool(set(s.engines) & {"wireguard", "openvpn"}),
        group="What to install",
        why="Each device gets its own keys, so you can revoke one without "
            "touching the others. Name them after the device, not the person."),

    # -- WireGuard ---------------------------------------------------------
    Question(
        key="wireguard.endpoint", prompt="Address clients should connect to",
        kind="text", default=_default_endpoint, validator=_v_endpoint,
        when=_wg, group="WireGuard", placeholder="vpn.example.com or 203.0.113.10",
        why="This goes into every client config. A hostname is better than an "
            "IP: if the server's address ever changes you update DNS once "
            "instead of reissuing every client."),

    Question(
        key="wireguard.port", prompt="UDP port",
        kind="int", default=lambda s, f: random_port(), validator=_v_port,
        when=_wg, group="WireGuard",
        why="Randomised by default. This is not a security control - a scan "
            "still finds it - but it keeps you out of the constant background "
            "noise aimed at 51820, which makes your logs readable."),

    Question(
        key="wireguard.allowed_ips", prompt="What should the VPN carry?",
        kind="choice", default="0.0.0.0/0,::/0", when=_wg, group="WireGuard",
        choices=[
            ("0.0.0.0/0,::/0", "All traffic - hides your browsing from the "
                               "local network"),
            ("__lan__", "Only traffic to the server's own network - a way in, "
                        "not a way out"),
        ],
        why="'All traffic' is what people mean by a VPN: your ISP and the "
            "coffee shop see only an encrypted connection to your server. "
            "'Only the server's network' is for reaching a home NAS or a "
            "private database without sending your whole day through it."),

    Question(
        key="wireguard.dns", prompt="DNS resolvers for clients",
        kind="text", default=lambda s, f: "9.9.9.9, 149.112.112.112",
        validator=_v_dns, when=_wg, group="WireGuard",
        why="If you route all traffic but keep your old DNS, every site you "
            "visit still leaks to that resolver - the leak the VPN was "
            "supposed to close. Quad9 is the default because it filters known "
            "malware domains and does not log to identify you."),

    Question(
        key="wireguard.subnet_v4", prompt="VPN subnet (IPv4)",
        kind="text", default=lambda s, f: netcalc.random_private_v4(),
        validator=_v_subnet4, when=_wg, advanced=True, group="WireGuard",
        why="Randomised inside 10/8 on purpose. If this collides with the "
            "network a client is sitting on - and half the world's routers "
            "are 192.168.1.0/24 - routing breaks in a way that is miserable "
            "to diagnose."),

    Question(
        key="wireguard.enable_ipv6", prompt="Give clients IPv6 addresses?",
        kind="bool", default=lambda s, f: f.has_ipv6, when=_wg,
        advanced=True, group="WireGuard",
        why="If the server has IPv6 and clients do not get it, an IPv6-capable "
            "client may route v6 traffic outside the tunnel entirely. That is "
            "a real leak."),

    Question(
        key="wireguard.mtu", prompt="MTU (0 = let the kernel decide)",
        kind="int", default=0, when=_wg, advanced=True, group="WireGuard",
        why="Leave at 0 unless you have a specific problem. A wrong MTU shows "
            "up as 'the tunnel connects but large pages hang', which is one "
            "of the hardest faults to recognise."),

    # -- OpenVPN -----------------------------------------------------------
    Question(
        key="openvpn.endpoint", prompt="Address clients should connect to",
        kind="text", default=_default_endpoint, validator=_v_endpoint,
        when=_ovpn, group="OpenVPN"),

    Question(
        key="openvpn.protocol", prompt="Protocol",
        kind="choice", default="udp", when=_ovpn, group="OpenVPN",
        choices=[("udp", "UDP - faster, the right default"),
                 ("tcp", "TCP - slower, but survives hostile networks")],
        why="UDP unless you need otherwise. TCP-over-TCP causes a meltdown "
            "under packet loss where both layers retransmit at once. Choose "
            "TCP only to run on 443 and look like HTTPS."),

    Question(
        key="openvpn.port", prompt="Port",
        kind="int",
        default=lambda s, f: 443 if s.openvpn.protocol == "tcp" else 1194,
        validator=_v_port, when=_ovpn, group="OpenVPN",
        why="443 with TCP is the combination that gets through captive "
            "portals and corporate firewalls, because blocking it would block "
            "the web."),

    Question(
        key="openvpn.cipher", prompt="Data channel cipher",
        kind="choice", default="AES-256-GCM", when=_ovpn, advanced=True,
        group="OpenVPN",
        choices=[("AES-256-GCM", "AES-256-GCM - hardware accelerated on any "
                                 "modern CPU"),
                 ("AES-128-GCM", "AES-128-GCM - slightly faster, still strong"),
                 ("CHACHA20-POLY1305", "ChaCha20-Poly1305 - faster on ARM and "
                                       "phones without AES instructions")],
        why="All three are AEAD, which means the cipher authenticates as well "
            "as encrypts. Tessera does not offer CBC options at all; the "
            "attacks on them are not theoretical."),

    Question(
        key="openvpn.cert_type", prompt="Certificate algorithm",
        kind="choice", default="ecdsa", when=_ovpn, advanced=True,
        group="OpenVPN",
        choices=[("ecdsa", "ECDSA P-256 - recommended"),
                 ("rsa", "RSA 3072 - for very old clients")],
        why="ECDSA gives the same security as RSA-3072 with a handshake an "
            "order of magnitude cheaper, which is noticeable on a small VPS "
            "with many clients reconnecting."),

    Question(
        key="openvpn.tls_sig", prompt="Control channel protection",
        kind="choice", default="crypt-v2", when=_ovpn, advanced=True,
        group="OpenVPN",
        choices=[("crypt-v2", "tls-crypt-v2 - a separate key per client"),
                 ("crypt", "tls-crypt - one shared key"),
                 ("auth", "tls-auth - authenticate only, no encryption")],
        why="tls-crypt-v2 means a leaked client key does not let an attacker "
            "probe the server as any other client. It also makes the port "
            "unidentifiable to scanners."),

    # -- Tailscale ---------------------------------------------------------
    Question(
        key="tailscale.auth_key", prompt="Tailscale auth key (optional)",
        kind="secret", default="", when=_ts, group="Tailscale",
        placeholder="tskey-auth-...",
        why="Generate one at login.tailscale.com/admin/settings/keys to join "
            "without opening a browser on the server. Leave blank and we will "
            "print a URL for you to approve instead. The key is written to a "
            "0600 file, used, then shredded."),

    Question(
        key="tailscale.advertise_exit_node", prompt="Offer this box as an exit node?",
        kind="bool", default=False, when=_ts, group="Tailscale",
        why="Lets your other devices send all their internet traffic through "
            "this server, which is the closest Tailscale gets to a classic "
            "VPN. You still have to approve it in the admin console."),

    Question(
        key="tailscale.login_server", prompt="Headscale server URL (optional)",
        kind="text", default="", when=_ts, advanced=True, group="Tailscale",
        placeholder="https://headscale.example.com",
        why="Point at your own coordination server instead of Tailscale's. "
            "This is the answer if the thing that bothers you about Tailscale "
            "is that a third party holds the key directory."),

    Question(
        key="tailscale.ssh", prompt="Enable Tailscale SSH?",
        kind="bool", default=False, when=_ts, advanced=True, group="Tailscale",
        why="Replaces SSH key management with your tailnet ACLs. Powerful, "
            "but it means your identity provider now controls shell access to "
            "this machine."),

    # -- Hardening ---------------------------------------------------------
    Question(
        key="hardening.sysctl_hardening", prompt="Apply kernel network hardening?",
        kind="bool", default=True, group="Hardening",
        why="Nine settings that matter on a machine forwarding other people's "
            "packets: ignore ICMP redirects, drop source-routed packets, "
            "enable reverse-path filtering. All reversible by deleting one file."),

    Question(
        key="hardening.block_rfc1918_from_vpn",
        prompt="Stop VPN clients reaching private networks?",
        kind="bool", default=True, group="Hardening",
        why="Without this, giving someone VPN access also gives them your "
            "home NAS, your router's admin page and anything else on the "
            "server's LAN. Turn it off only if reaching that LAN is the point."),

    Question(
        key="hardening.fail2ban", prompt="Install fail2ban for SSH?",
        kind="bool", default=lambda s, f: s.profile == "paranoid",
        group="Hardening",
        why="Bans addresses after repeated SSH failures. Most of the noise in "
            "a fresh VPS log is exactly this, and it stops within the hour."),

    Question(
        key="hardening.unattended_upgrades",
        prompt="Enable automatic security updates?",
        kind="bool", default=lambda s, f: s.profile == "paranoid",
        group="Hardening",
        why="Security patches only, applied nightly. A VPN server you log "
            "into twice a year is otherwise a year behind on kernel fixes."),

    Question(
        key="hardening.disable_ssh_password_auth",
        prompt="Disable SSH password login?",
        kind="bool", default=lambda s, f: s.profile == "paranoid",
        group="Hardening",
        why="The single change that removes the entire SSH brute-force "
            "category. Tessera refuses to do it unless an authorized_keys "
            "file already exists, and validates the config before reloading - "
            "but keep your session open and test a second one before you "
            "log out."),
]


# --------------------------------------------------------------------------- #
# Applying answers
# --------------------------------------------------------------------------- #
def visible_questions(spec: InstallSpec, facts: Facts,
                      include_advanced: bool = False) -> List[Question]:
    out = []
    for q in QUESTIONS:
        if not q.applies(spec, facts):
            continue
        if q.advanced and not include_advanced:
            continue
        out.append(q)
    return out


def get_value(spec: InstallSpec, key: str) -> Any:
    obj: Any = spec
    for part in key.split("."):
        obj = getattr(obj, part)
    return obj


def set_value(spec: InstallSpec, key: str, value: Any,
              record: bool = True) -> None:
    """Assign into the spec, coercing to the field's declared type.

    ``record`` marks the key as explicitly answered so ``fill_defaults`` leaves
    it alone.  Defaults are applied with ``record=False``.
    """
    if record and key not in spec.answered:
        spec.answered.append(key)
    parts = key.split(".")
    obj: Any = spec
    for part in parts[:-1]:
        obj = getattr(obj, part)
    leaf = parts[-1]
    current = getattr(obj, leaf, None)

    if key == "wireguard.allowed_ips" and value == "__lan__":
        value = spec.wireguard.subnet_v4
    if key.endswith(".dns") and isinstance(value, str):
        value = [e.strip() for e in value.replace(",", " ").split() if e.strip()]
    elif isinstance(current, bool):
        value = _as_bool(value)
    elif isinstance(current, int) and not isinstance(current, bool):
        value = int(value)
    elif isinstance(current, list) and isinstance(value, str):
        value = [e.strip() for e in value.replace(",", " ").split() if e.strip()]
    setattr(obj, leaf, value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("y", "yes", "true", "1", "on")


def answer(spec: InstallSpec, facts: Facts, key: str, value: Any) -> str:
    """Validate and apply one answer.  Returns a non-blocking warning, if any."""
    q = next((x for x in QUESTIONS if x.key == key), None)
    if q is None:
        raise ValidationError("no such question: {}".format(key))
    ok, msg = q.validate(value, spec, facts)
    if not ok:
        raise ValidationError("{}: {}".format(q.prompt, msg))
    set_value(spec, key, value)
    return msg


def fill_defaults(spec: InstallSpec, facts: Facts) -> InstallSpec:
    """Answer every unanswered question with its default.

    Anything already chosen - by a CLI flag, by the wizard, or by a profile -
    is left exactly as it is.  Run it as many times as you like.
    """
    for q in QUESTIONS:
        if q.key in spec.answered:
            continue
        if not q.applies(spec, facts):
            continue
        value = q.resolve_default(spec, facts)
        if value is None:
            continue
        set_value(spec, q.key, value, record=False)
    return spec


def mark_answered(spec: InstallSpec, *keys: str) -> InstallSpec:
    """Protect values set outside the interview, e.g. by a command-line flag."""
    for k in keys:
        if k not in spec.answered:
            spec.answered.append(k)
    return spec

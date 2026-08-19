"""A simulated Ubuntu server, so you can try Tessera without owning a VPS.

Two reasons this exists rather than being test-only scaffolding:

  * Evaluation.  Nobody should have to provision a server to find out whether
    they like a tool.  ``tessera install demo`` walks the whole interview,
    renders real configs with real keys, and shows exactly what would run.
  * CI.  Every code path except the actual shell execution is exercised on a
    machine with no network and no root.

It is a Transport that answers plausibly and records everything, so the plans,
the rendered configs and the generated keys are all genuine - only the
execution is simulated.  Nothing here is ever used against a real target: the
demo is selected explicitly by naming ``demo`` as the target.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .models import Facts
from .transport import CommandResult, Transport

# Answers keyed by a regex matched against the command.
_RESPONSES = {
    r"\bwg pubkey\b": "hK3vN9pQwXcR2mT7yB4jL8sF1dG6aZ0eV5nU3iO2kP4=",
    r"uname -r": "6.8.0-45-generic",
    r"wg --version": "wireguard-tools v1.0.20210914",
    r"openvpn --version": "OpenVPN 2.6.12 x86_64-pc-linux-gnu",
    r"tailscale version": "1.80.2",
    r"wg show \S+ dump": (
        "hK3vN9pQwXcR2mT7yB4jL8sF1dG6aZ0eV5nU3iO2kP4=\t(none)\t51820\toff\n"
        "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4c=\t(psk)\t"
        "198.51.100.22:41820\t10.66.66.2/32\t1755500000\t184320000\t"
        "22150000\t25\n"
        "cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5cD6e=\t(psk)\t(none)\t"
        "10.66.66.3/32\t0\t0\t0\t25\n"),
    r"sshd -T": "port 22\npasswordauthentication no\npermitrootlogin prohibit-password\n",
    r"grep -c '\^Inst.*security'": "0",
    r"ss -tulnH": "22\n",
    r"cat /etc/openvpn/server/server\.conf": (
        "port 1194\nproto udp\ndev tun\ntopology subnet\n"
        "server 10.8.0.0 255.255.255.0\nca ca.crt\ncrl-verify crl.pem\n"
        "auth SHA256\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM\n"
        "tls-server\ntls-version-min 1.2\ntls-crypt-v2 tls-crypt-v2.key\n"
        "verb 3\n"),
    r"id -u": "0",
}


class DemoTransport(Transport):
    """Answers plausibly, records everything, changes nothing."""

    label = "demo (simulated Ubuntu 24.04 server)"
    is_root = True

    def __init__(self) -> None:
        self.commands: List[str] = []
        self.files: Dict[str, str] = {}

    def run(self, command: str, *, check: bool = False, timeout: int = 300,
            sink=None, input_text: Optional[str] = None) -> CommandResult:
        self.commands.append(command)
        for pattern, output in _RESPONSES.items():
            if re.search(pattern, command):
                if sink:
                    for line in output.splitlines():
                        sink("out", line)
                return CommandResult(command, 0, output + "\n", "", 0.02)
        if sink:
            sink("out", "(demo) would run: {}".format(command.splitlines()[0][:110]))
        return CommandResult(command, 0, "", "", 0.02)

    def run_root(self, command: str, **kw) -> CommandResult:
        return self.run(command, **kw)

    def write_file(self, path: str, content: str, mode: str = "0600") -> None:
        self.files[path] = content

    def read_file(self, path: str) -> str:
        if path in self.files:
            return self.files[path]
        if path.endswith("ca.crt"):
            return _demo_certificate()
        if path.endswith("TESSERA_SERVER_NAME"):
            return "tessera_demoserver01\n"
        if path.endswith(".crt"):
            return _demo_certificate()
        return ""

    def file_exists(self, path: str) -> bool:
        return path in self.files

    def which(self, binary: str) -> Optional[str]:
        return "/usr/bin/" + binary

    def can_escalate(self) -> bool:
        return True


def facts() -> Facts:
    """The server the demo pretends to be."""
    return Facts(
        os_id="ubuntu", os_name="Ubuntu 24.04.1 LTS", version_id="24.04",
        version_codename="noble", family="debian", pkg="apt",
        kernel="6.8.0-45-generic", arch="x86_64", init="systemd",
        virt="kvm", public_ipv4="203.0.113.47", private_ipv4="10.0.0.5",
        nic="eth0", has_tun=True, has_ipv6=True, firewall="iptables",
        selinux=False, behind_nat=True, installed={})


# The demo signs a real certificate rather than shipping a fake blob.  A
# hand-written PEM that does not parse turns the demo into a bug report about
# ASN.1, which is not what anyone is trying to learn here.  Generated once per
# process, discarded on exit, and usable for nothing.
_CERT_CACHE = {}


def _demo_certificate() -> str:
    if "pem" in _CERT_CACHE:
        return _CERT_CACHE["pem"]
    try:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                             "Tessera Demo CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                               critical=True)
                .sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    except Exception:                                          # noqa: BLE001
        pem = ""
    _CERT_CACHE["pem"] = pem
    return pem

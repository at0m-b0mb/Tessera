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


def state_path() -> str:
    """Where the simulated server's disk lives between commands."""
    from .fleet import config_dir
    import os
    return os.path.join(config_dir(), "demo-server.json")


def reset() -> bool:
    """Wipe the simulated server.  Returns True if there was anything to wipe."""
    import os
    p = state_path()
    if os.path.exists(p):
        os.remove(p)
        return True
    return False


class DemoTransport(Transport):
    """Answers plausibly, records everything, changes nothing real.

    Its virtual disk persists between commands, in a single JSON file beside
    your config.  Without that, ``tessera install demo`` followed by ``tessera
    peer add demo`` would fail, because the second command would meet a server
    with no VPN on it - and the whole point of the demo is to let someone walk
    the real workflow before they own a server.
    """

    label = "demo (simulated Ubuntu 24.04 server)"
    is_root = True

    def __init__(self, persist: bool = True) -> None:
        self.commands: List[str] = []
        self.files: Dict[str, str] = {}
        self._persist = persist
        if persist:
            self._load()

    def run(self, command: str, *, check: bool = False, timeout: int = 300,
            sink=None, input_text: Optional[str] = None) -> CommandResult:
        self.commands.append(command)
        import re as _re
        # `ls -1 /etc/wireguard/*.conf` is how adopt discovers an install.
        # Without answering it from the virtual disk, the headline feature of
        # this release cannot be tried on the demo server at all.
        ls = _re.match(r"^ls -1 (\S+)\s*2?>?", command.strip())
        if ls:
            import fnmatch
            pattern = ls.group(1).strip("'\"")
            hits = sorted(f for f in self.files
                          if fnmatch.fnmatch(f, pattern))
            if hits:
                return CommandResult(command, 0, "\n".join(hits) + "\n", "", 0.01)
            return CommandResult(command, 1, "", "No such file", 0.01)
        dump = _re.search(r"wg show (\S+) dump", command)
        if dump:
            return CommandResult(
                command, 0, self._wg_dump(dump.group(1).strip("'\"")), "", 0.02)
        m = _re.match(r"^cat (?:-- )?(\S+)\s*$", command.strip())
        if m:
            path = m.group(1).strip("'\"")
            if path in self.files:
                return CommandResult(command, 0, self.files[path], "", 0.01)
        for pattern, output in _RESPONSES.items():
            if re.search(pattern, command):
                if sink:
                    for line in output.splitlines():
                        sink("out", line)
                return CommandResult(command, 0, output + "\n", "", 0.02)
        if sink:
            sink("out", "(demo) would run: {}".format(command.splitlines()[0][:110]))
        return CommandResult(command, 0, "", "", 0.02)

    def _wg_dump(self, iface: str) -> str:
        """Generate `wg show dump` from the config this server actually has.

        A canned response would contradict whatever the user just configured -
        different subnet, peers that do not exist - and the demo is supposed to
        show people how the real thing behaves, not a postcard of it.
        """
        import time
        from .adopt import parse_wg_conf
        conf = self.files.get("/etc/wireguard/{}.conf".format(iface))
        if not conf:
            return ""
        parsed = parse_wg_conf(conf)
        rows = ["{}\t(none)\t{}\toff".format(
            _RESPONSES[r"\bwg pubkey\b"], parsed["port"] or 51820)]
        now = int(time.time())
        for index, peer in enumerate(parsed["peers"]):
            # First peer looks recently connected, the rest never have, so the
            # dashboard shows both states.
            handshake = (now - 47) if index == 0 else 0
            rx, tx = (184320000, 22150000) if index == 0 else (0, 0)
            rows.append("{}\t{}\t{}\t{}\t{}\t{}\t{}\t25".format(
                peer["public_key"],
                "(psk)" if peer["preshared_key"] else "(none)",
                "198.51.100.22:41820" if index == 0 else "(none)",
                ",".join(peer["allowed_ips"]), handshake, rx, tx))
        return "\n".join(rows) + "\n"

    def run_root(self, command: str, **kw) -> CommandResult:
        result = self.run(command, **kw)
        self._apply_writes(command)
        self._apply_removals(command)
        return result

    def _apply_writes(self, command: str) -> None:
        """Honour simple `> /path` and `>> /path` redirects.

        Several install steps create files with a redirect rather than through
        write_file - `wg genkey > key`, `printf ... >> sysctl.conf`. Without
        modelling those, `tessera verify demo` reports them as missing and the
        first thing anyone trying the demo sees is a drift warning about a
        server that is perfectly fine.
        """
        import re
        for match in re.finditer(r">>?\s*(/[\w./@-]+)", command):
            path = match.group(1)
            if path.startswith("/dev/"):
                continue
            self.files.setdefault(path, "# created by the simulated server\n")
        # Easy-RSA's PKI is produced by running ./easyrsa, which the demo does
        # not execute. Without modelling the files it leaves behind, `verify
        # demo` correctly reports a missing PKI - which is true of the
        # simulation and false of the thing it is simulating.
        if "easyrsa" in command and ("init-pki" in command or "build-ca" in command):
            base = "/etc/openvpn/server/easy-rsa"
            self.files.setdefault(base + "/easyrsa", "#!/bin/sh\n")
            self.files.setdefault(base + "/TESSERA_SERVER_NAME",
                                  "tessera_demoserver01\n")
            self.files.setdefault(base + "/pki/ca.crt", _demo_certificate())
            self.files.setdefault(
                base + "/pki/index.txt",
                "V\t350101000000Z\t\t01\tunknown\t/CN=tessera_demoserver01\n")
            self.files.setdefault(base + "/pki/crl.pem", "")
        # A signed client certificate lands in the index, so `peer list` and
        # `verify` agree with each other afterwards.
        m_sign = re.search(r"sign-req client (\S+)", command)
        if m_sign:
            name = m_sign.group(1).strip("'\"")
            index = "/etc/openvpn/server/easy-rsa/pki/index.txt"
            serial = "{:02X}".format(
                len(self.files.get(index, "").splitlines()) + 1)
            self.files[index] = self.files.get(index, "") + (
                "V\t280101000000Z\t\t{}\tunknown\t/CN={}\n".format(serial, name))
            self.files.setdefault(
                "/etc/openvpn/server/easy-rsa/pki/issued/{}.crt".format(name),
                _demo_certificate())

        # `mkdir -p` makes directories the inventory later looks for.
        for chunk in re.findall(r"mkdir -p ([^&|;\n]+)", command):
            for part in chunk.split():
                part = part.strip("'\"")
                if part.startswith("/"):
                    self.files.setdefault(part.rstrip("/") + "/.dir", "")
        self._save()

    def _apply_removals(self, command: str) -> None:
        """Honour rm/shred/rmdir against the virtual disk.

        Only the arguments *to* those commands, not every path-shaped token in
        a script that happens to contain one. The first version scanned the
        whole command, so the OpenVPN signing step - which does `cd
        .../easy-rsa` and later `rm -f ...req` - deleted the entire PKI, and
        the demo then reported a missing CA that the real thing would have had.
        """
        import re
        import shlex

        # Split into statements the way a shell would, so `rm`'s arguments end
        # where the next command begins.
        for statement in re.split(r"(?:\n|&&|\|\||;|\|)", command):
            statement = statement.strip()
            if not statement:
                continue
            try:
                words = shlex.split(statement)
            except ValueError:
                continue
            if not words:
                continue
            # Skip `command -v shred >/dev/null` style guards.
            while words and words[0] in ("command", "test", "[", "then", "do",
                                         "(", "if"):
                words = words[1:]
            if not words or words[0] not in ("rm", "shred", "rmdir"):
                continue
            for arg in words[1:]:
                if arg.startswith("-") or not arg.startswith("/"):
                    continue
                for existing in list(self.files):
                    if existing == arg or existing.startswith(
                            arg.rstrip("/") + "/"):
                        self.files.pop(existing, None)
        self._save()

    def write_file(self, path: str, content: str, mode: str = "0600") -> None:
        self.files[path] = content
        self._save()

    def read_file(self, path: str) -> str:
        if path in self.files:
            return self.files[path]
        if path.endswith("ca.crt") or path.endswith(".crt"):
            return _demo_certificate()
        if path.endswith("TESSERA_SERVER_NAME"):
            return "tessera_demoserver01\n"
        return ""

    def _load(self) -> None:
        import json
        import os
        p = state_path()
        if not os.path.exists(p):
            return
        try:
            with open(p, "r", encoding="utf-8") as fh:
                self.files = json.load(fh).get("files", {})
        except Exception:                                      # noqa: BLE001
            self.files = {}

    def _save(self) -> None:
        if not self._persist:
            return
        import json
        import os
        p = state_path()
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            tmp = p + ".tmp"
            # 0600 even though these keys are simulated: this file has the
            # same shape as a real one, and a demo that models sloppy
            # permissions is teaching the wrong habit.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"files": self.files}, fh, indent=2, sort_keys=True)
            os.replace(tmp, p)
        except Exception:                                      # noqa: BLE001
            pass

    def file_exists(self, path: str) -> bool:
        if path in self.files:
            return True
        prefix = path.rstrip("/") + "/"
        return any(f.startswith(prefix) for f in self.files)

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

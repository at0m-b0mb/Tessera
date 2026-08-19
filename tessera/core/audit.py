"""Post-install security audit.

This does not grade your VPN out of a hundred and award it an A+.  Scores like
that are comforting and wrong: they average a fatal flaw together with nine
cosmetic passes and hand you a B.

Instead the audit returns findings, and the *worst* finding sets the verdict.
One failure means the whole thing reports as failing, no matter how many checks
passed, because that is how security actually works.  A server with perfect
ciphers and password SSH login is not a good server.

Every check reads.  Nothing here changes the system.
"""

from __future__ import annotations

import re
import shlex
from typing import Dict, List, Optional

from .models import Facts, Finding
from .state import ServerState
from .transport import Transport

# Verdicts, worst first.
VERDICTS = ["fail", "warn", "pass"]


def run(t: Transport, f: Facts, state: Optional[ServerState]) -> List[Finding]:
    """Run every applicable check and return the findings."""
    out: List[Finding] = []
    out += _check_ssh(t)
    out += _check_updates(t, f)
    out += _check_firewall(t, f)
    out += _check_kernel(t, f)
    out += _check_disk_encryption(t)
    if state:
        for engine in state.installed_engines:
            if engine == "wireguard":
                out += _check_wireguard(t, state)
            elif engine == "openvpn":
                out += _check_openvpn(t, state)
            elif engine == "tailscale":
                out += _check_tailscale(t)
        out += _check_permissions(t, state)
    return out


def verdict(findings: List[Finding]) -> str:
    """The worst level present.  One failure fails the whole audit."""
    if any(x.level == "fail" for x in findings):
        return "fail"
    if any(x.level == "warn" for x in findings):
        return "warn"
    return "pass"


def tally(findings: List[Finding]) -> Dict[str, int]:
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for x in findings:
        counts[x.level] = counts.get(x.level, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _check_ssh(t: Transport) -> List[Finding]:
    out: List[Finding] = []
    # sshd -T prints the effective configuration, which is the only thing that
    # matters. Reading sshd_config misses drop-ins and Match blocks.
    eff = t.run_root("sshd -T 2>/dev/null").stdout.lower()
    if not eff:
        return [Finding("info", "SSH configuration not readable",
                        "Could not run 'sshd -T'.", engine="")]

    if "passwordauthentication yes" in eff:
        out.append(Finding(
            "fail", "SSH accepts passwords",
            "sshd is configured with PasswordAuthentication yes.",
            "Add an SSH key, confirm it works, then set PasswordAuthentication "
            "no. Tessera can do this for you under Harden.",
            weight=3))
    else:
        out.append(Finding("pass", "SSH is key-only",
                           "Password authentication is disabled."))

    if "permitrootlogin yes" in eff:
        out.append(Finding(
            "warn", "Root can log in over SSH with a password",
            "PermitRootLogin is 'yes'.",
            "Set it to 'prohibit-password' so root can only use a key."))

    m = re.search(r"^port (\d+)", eff, re.M)
    if m and m.group(1) == "22":
        out.append(Finding(
            "info", "SSH is on the default port",
            "Port 22 attracts constant automated scanning.",
            "Moving it reduces log noise. It is not a security control on its "
            "own - do not rely on it instead of key-only auth."))
    return out


def _check_updates(t: Transport, f: Facts) -> List[Finding]:
    if f.family == "debian":
        r = t.run_root("apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null "
                       "| grep -c '^Inst.*security' || true")
        n = int(r.out) if r.out.isdigit() else 0
        if n > 0:
            return [Finding(
                "fail" if n > 10 else "warn",
                "{} security update{} pending".format(n, "" if n == 1 else "s"),
                "Packages with published security fixes are not installed.",
                "Run 'apt-get update && apt-get upgrade'. Consider enabling "
                "unattended-upgrades so this cannot drift again.",
                weight=2)]
        return [Finding("pass", "Security updates are current",
                        "No pending security packages.")]
    if f.family == "rhel":
        r = t.run_root("dnf -q updateinfo list security 2>/dev/null | wc -l")
        n = int(r.out) if r.out.isdigit() else 0
        if n > 0:
            return [Finding("warn", "{} security advisories pending".format(n),
                            "", "Run 'dnf upgrade --security'.")]
    return [Finding("info", "Update status not checked",
                    "No update check implemented for this distribution.")]


def _check_firewall(t: Transport, f: Facts) -> List[Finding]:
    if f.firewall == "none":
        return [Finding(
            "warn", "No firewall is active",
            "Nothing is filtering inbound traffic.",
            "Every service listening on this box is reachable from the whole "
            "internet. Enable ufw or firewalld and allow only what you need.")]
    listening = t.run_root(
        "ss -tulnH 2>/dev/null | awk '$5 !~ /127\\.0\\.0\\.1|\\[::1\\]/ "
        "{print $1, $5}' | sort -u").stdout.strip()
    exposed = [l for l in listening.splitlines() if l.strip()]
    if len(exposed) > 6:
        return [Finding(
            "warn", "{} services listen on public addresses".format(len(exposed)),
            "\n".join(exposed[:12]),
            "Each one is attack surface on a machine whose job is to be a VPN. "
            "Bind what you can to localhost.",
            weight=2)]
    return [Finding("pass", "Firewall active, exposure is small",
                    "{} managing {} public listener(s).".format(
                        f.firewall, len(exposed)))]


def _check_kernel(t: Transport, f: Facts) -> List[Finding]:
    out: List[Finding] = []
    running = t.run("uname -r").out
    if f.family == "debian":
        newest = t.run_root(
            "ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|.*vmlinuz-||' "
            "| sort -V | tail -1").out
        if newest and running and newest != running:
            out.append(Finding(
                "warn", "A newer kernel is installed but not running",
                "Running {}, installed {}.".format(running, newest),
                "Reboot to pick up the new kernel. Until you do, any kernel "
                "security fix in it is not applied.",
                weight=2))
    if t.file_exists("/var/run/reboot-required"):
        out.append(Finding("warn", "The server is waiting for a reboot",
                           "/var/run/reboot-required exists.",
                           "Schedule a reboot."))
    if not out:
        out.append(Finding("pass", "Kernel is current",
                           "Running {}.".format(running)))
    return out


def _check_disk_encryption(t: Transport) -> List[Finding]:
    r = t.run_root("lsblk -o TYPE 2>/dev/null | grep -qi crypt")
    if r.ok:
        return [Finding("pass", "Disk encryption is in use",
                        "A dm-crypt layer is present.")]
    return [Finding(
        "info", "The disk is not encrypted",
        "No dm-crypt/LUKS layer was found.",
        "On a VPS the host can read your disk regardless, so this is often out "
        "of your control. It matters because it is the only thing that makes "
        "deleting a private key genuinely irreversible - see the note in the "
        "uninstaller about shred on flash storage.")]


def _check_wireguard(t: Transport, state: ServerState) -> List[Finding]:
    out: List[Finding] = []
    rec = state.engine("wireguard")
    iface = (rec.config or {}).get("interface", "wg0") if rec else "wg0"
    dump = t.run_root("wg show {} dump 2>/dev/null".format(shlex.quote(iface)))
    if not dump.ok or not dump.stdout.strip():
        return [Finding("fail", "WireGuard is not running",
                        "'wg show {}' returned nothing.".format(iface),
                        "Check 'systemctl status wg-quick@{}'.".format(iface),
                        engine="wireguard", weight=3)]

    lines = [l for l in dump.stdout.splitlines()[1:] if l.strip()]
    without_psk = [l for l in lines if l.split("\t")[1] in ("(none)", "")]
    if without_psk:
        out.append(Finding(
            "warn", "{} peer(s) have no preshared key".format(len(without_psk)),
            "A preshared key adds a symmetric secret on top of the Curve25519 "
            "handshake.",
            "Recreate those peers with Tessera, which always sets one. It is "
            "the difference between 'recorded today, decrypted when quantum "
            "computers arrive' and 'still needs a 256-bit secret they never "
            "saw'.",
            engine="wireguard", weight=2))
    else:
        out.append(Finding("pass", "All WireGuard peers use a preshared key",
                           engine="wireguard"))

    stale = 0
    import time as _t
    now = int(_t.time())
    for l in lines:
        parts = l.split("\t")
        if len(parts) > 4 and parts[4].isdigit():
            hs = int(parts[4])
            if hs == 0 or now - hs > 90 * 86400:
                stale += 1
    if stale:
        out.append(Finding(
            "info", "{} peer(s) have not connected in 90 days".format(stale),
            "", "Peers you no longer recognise are peers you should remove. "
                "Every configured key is a way in.",
            engine="wireguard"))
    return out


def _check_openvpn(t: Transport, state: ServerState) -> List[Finding]:
    out: List[Finding] = []
    conf = t.run_root("cat /etc/openvpn/server/server.conf 2>/dev/null").stdout
    if not conf:
        return [Finding("fail", "OpenVPN config not found",
                        "/etc/openvpn/server/server.conf is missing.",
                        engine="openvpn", weight=3)]

    if re.search(r"^\s*(comp-lzo|compress)", conf, re.M):
        out.append(Finding(
            "fail", "OpenVPN compression is enabled",
            "The config contains a compression directive.",
            "Remove it. Compressing before encrypting leaks plaintext length, "
            "which is the VORACLE attack: an attacker who can inject known "
            "data into your traffic can recover secrets from it.",
            engine="openvpn", weight=3))
    else:
        out.append(Finding("pass", "OpenVPN compression is off",
                           "No compression directive present.", engine="openvpn"))

    m = re.search(r"^\s*(?:data-ciphers|cipher)\s+(\S+)", conf, re.M)
    if m:
        cipher = m.group(1).upper()
        if "GCM" in cipher or "CHACHA20" in cipher:
            out.append(Finding("pass", "AEAD cipher in use",
                               cipher, engine="openvpn"))
        else:
            out.append(Finding(
                "fail", "OpenVPN uses a non-AEAD cipher",
                cipher,
                "Switch to AES-256-GCM. CBC ciphers need a separate MAC, and "
                "getting that wrong is where padding-oracle attacks live.",
                engine="openvpn", weight=3))

    if not re.search(r"^\s*crl-verify", conf, re.M):
        out.append(Finding(
            "warn", "No certificate revocation list is configured",
            "server.conf has no crl-verify line.",
            "Without it, revoking a client certificate has no effect and the "
            "old certificate keeps working until it expires.",
            engine="openvpn", weight=2))

    if not re.search(r"^\s*tls-(crypt|auth|crypt-v2)", conf, re.M):
        out.append(Finding(
            "warn", "The control channel is unprotected",
            "No tls-crypt, tls-crypt-v2 or tls-auth directive.",
            "Anyone can identify the service and make it perform handshake "
            "work. Prefer tls-crypt-v2.", engine="openvpn", weight=2))

    exp = t.run_root(
        "openssl x509 -in /etc/openvpn/server/ca.crt -noout -checkend "
        "2592000 2>/dev/null")
    if not exp.ok:
        out.append(Finding(
            "warn", "The CA certificate expires within 30 days",
            "", "Every client stops connecting when it does.",
            engine="openvpn", weight=2))
    return out


def _check_tailscale(t: Transport) -> List[Finding]:
    r = t.run_root("tailscale status --json 2>/dev/null")
    if not r.ok or not r.stdout.strip():
        return [Finding("warn", "Tailscale is not connected",
                        "'tailscale status' returned nothing.",
                        "Run 'tailscale up'.", engine="tailscale")]
    out = [Finding("pass", "Tailscale is connected", engine="tailscale")]
    try:
        import json
        data = json.loads(r.stdout)
        if not (data.get("Self") or {}).get("ShieldsUp"):
            out.append(Finding(
                "info", "Shields are down",
                "Other devices on your tailnet can open connections to this "
                "machine.",
                "If this box only needs to reach out, 'tailscale up "
                "--shields-up' makes it unreachable from the tailnet.",
                engine="tailscale"))
    except Exception:                                          # noqa: BLE001
        pass
    return out


def _check_permissions(t: Transport, state: ServerState) -> List[Finding]:
    """Every file we created should still have the mode we gave it."""
    expected = {
        "/etc/wireguard": "700", "/etc/tessera": "700",
        "/etc/tessera/state.json": "600",
        "/etc/openvpn/server": "700",
    }
    bad: List[str] = []
    for path, mode in expected.items():
        if not t.file_exists(path):
            continue
        actual = t.run_root("stat -c '%a' {} 2>/dev/null".format(
            shlex.quote(path))).out
        if actual and actual != mode:
            bad.append("{} is {} (expected {})".format(path, actual, mode))
    # Any world-readable private key is a hard failure.
    loose = t.run_root(
        "find /etc/wireguard /etc/tessera /etc/openvpn -type f "
        "\\( -name '*.key' -o -name '*.conf' -o -name 'state.json' \\) "
        "-perm /o+rwx 2>/dev/null").stdout.strip()
    if loose:
        return [Finding(
            "fail", "Key material is readable by every user on the server",
            loose,
            "Run 'chmod -R go-rwx /etc/wireguard /etc/tessera'. Any local "
            "account can currently copy your keys.",
            weight=3)]
    if bad:
        return [Finding("warn", "File permissions have drifted",
                        "\n".join(bad), "Re-run the installer to reset them.")]
    return [Finding("pass", "Key material permissions are correct",
                    "Private keys are readable only by root.")]

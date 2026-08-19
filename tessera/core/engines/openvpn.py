"""OpenVPN.

Slower than WireGuard and far more configuration surface, but it is the engine
that gets through hostile networks: it speaks TCP on port 443, where it is
indistinguishable from HTTPS to anything short of deep packet inspection, and
it supports certificates with real revocation.

Tessera's OpenVPN differs from the reference installer in one structural way:
**client private keys are generated on your desktop and never sent to the
server.**  Easy-RSA's ``build-client-full`` makes the keypair on the server, so
the server has held the private key of every client it ever issued.  Tessera
generates the key locally, uploads only a certificate signing request, and asks
Easy-RSA to ``import-req`` and ``sign-req``.  That is the flow every public CA
has used for decades, and it means a compromised server leaks no client
identities.

Defaults are chosen, not inherited:

  * **ECDSA on P-256**, not RSA.  Same security as RSA-3072 with a handshake
    that is an order of magnitude cheaper, which matters on a small VPS.
  * **AES-256-GCM**.  AEAD, so there is no separate MAC to get wrong, and no
    CBC padding oracle.
  * **tls-crypt-v2**, which encrypts the control channel with a per-client key.
    An attacker who does not hold a client key cannot even tell the port is
    OpenVPN, and cannot force the server to do handshake work.
  * **Compression off.**  Compression before encryption leaks plaintext length,
    which is the VORACLE attack.  There is no safe way to enable it.
"""

from __future__ import annotations

import re
import shlex
from typing import Dict, List, Tuple

from .. import netcalc
from ..errors import TesseraError, ValidationError
from ..keys import (cert_expiry, cert_fingerprint, generate_client_csr,
                    random_token)
from ..models import OpenVPNConfig, Peer
from ..plan import Plan, Step, StepKind
from .base import (Engine, EngineContext, already_installed, close_port_cmd,
                   masquerade_rules, open_port_cmd, pkg_install, pkg_refresh,
                   pkg_remove, svc_enable_start, svc_is_active,
                   svc_stop_disable, sysctl_step)

# Pinned and checksummed.  An installer that pipes an unverified tarball from
# the internet into your PKI directory is not a security tool.
EASYRSA_VERSION = "3.2.6"
EASYRSA_SHA256 = "c2572990ce91112eef8d1b8e4a3b58790da95b68501785c621f69121dfbd22d7"
EASYRSA_URL = ("https://github.com/OpenVPN/easy-rsa/releases/download/"
               "v{v}/EasyRSA-{v}.tgz".format(v=EASYRSA_VERSION))

SERVER_DIR = "/etc/openvpn/server"
EASYRSA_DIR = SERVER_DIR + "/easy-rsa"
PKI = EASYRSA_DIR + "/pki"

PACKAGES = {
    "debian": ["openvpn", "easy-rsa", "iptables", "openssl", "ca-certificates",
               "curl", "tar"],
    "rhel":   ["openvpn", "iptables", "openssl", "ca-certificates", "curl", "tar"],
    "arch":   ["openvpn", "iptables", "openssl", "ca-certificates", "curl", "tar"],
    "alpine": ["openvpn", "iptables", "openssl", "ca-certificates", "curl", "tar"],
    "suse":   ["openvpn", "iptables", "openssl", "ca-certificates", "curl", "tar"],
}

CIPHERS = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"]
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class OpenVPNEngine(Engine):
    name = "openvpn"
    label = "OpenVPN"
    blurb = ("The compatibility choice. Runs on TCP 443 where it looks like "
             "ordinary HTTPS, and has real certificate revocation.")
    strengths = (
        "Gets through restrictive networks by speaking TCP 443",
        "Certificates can be revoked centrally and immediately",
        "A client exists for every platform made in the last twenty years",
        "Per-client control-channel keys hide the service from scanners",
    )
    tradeoffs = (
        "Runs in userspace, so it is several times slower than WireGuard",
        "A large configuration surface, most of which can be set unsafely",
        "Roaming between networks forces a full renegotiation",
    )

    # ---------------------------------------------------------------- install
    def plan_install(self, ctx: EngineContext) -> Plan:
        f, cfg = ctx.facts, ctx.spec.openvpn
        plan = Plan("Install OpenVPN on {}".format(ctx.spec.target.display()))
        server_name = "tessera_" + random_token(12)

        packages = PACKAGES.get(f.family, PACKAGES["debian"])
        pre = {p: already_installed(ctx.transport, f, p) for p in packages}
        for p, existed in pre.items():
            ctx.note("package", p, self.name, pre_existing=existed)

        plan.add(Step("ovpn-refresh", "Refresh package lists", StepKind.PACKAGE,
                      command=pkg_refresh(f), critical=False, timeout=600,
                      why="So we get a current OpenVPN with AEAD support."))
        plan.add(Step("ovpn-packages", "Install OpenVPN and dependencies",
                      StepKind.PACKAGE, command=pkg_install(f, packages),
                      undo=pkg_remove(f, [p for p, e in pre.items() if not e]) or "true",
                      timeout=900,
                      why="OpenVPN itself plus the tools its PKI needs."))
        plan.add(Step("ovpn-verify", "Verify openvpn is installed",
                      StepKind.CHECK, command="command -v openvpn >/dev/null"))
        plan.add(Step(
            "ovpn-version", "Require OpenVPN 2.5 or newer", StepKind.CHECK,
            command=("v=$(openvpn --version | head -1 | awk '{print $2}'); "
                     "major=${v%%.*}; minor=$(echo \"$v\" | cut -d. -f2); "
                     "[ \"$major\" -gt 2 ] || { [ \"$major\" -eq 2 ] && "
                     "[ \"$minor\" -ge 5 ]; }"),
            why="tls-crypt-v2 and ChaCha20 arrived in 2.5. Below that we would "
                "silently fall back to weaker settings, so we stop instead."))

        plan.add(Step("ovpn-dirs", "Create the server directory", StepKind.CONFIG,
                      command=("mkdir -p {s}/ccd /etc/tessera /var/log/openvpn "
                               "&& chmod 700 {s} /etc/tessera").format(
                                   s=shlex.quote(SERVER_DIR)),
                      why="0700: this tree will hold the CA private key."))
        for d in (SERVER_DIR, "/var/log/openvpn"):
            ctx.note("dir", d, self.name)

        # -- Easy-RSA, verified ----------------------------------------------
        plan.add(Step(
            "ovpn-easyrsa-fetch", "Download Easy-RSA {}".format(EASYRSA_VERSION),
            StepKind.CONFIG,
            command=("set -eu\n"
                     "tmp=$(mktemp /tmp/tessera-easyrsa.XXXXXX.tgz)\n"
                     "curl -fL --retry 3 --max-time 120 -o \"$tmp\" {url}\n"
                     "echo '{sha}  '\"$tmp\" | sha256sum -c - >/dev/null\n"
                     "mkdir -p {d}\n"
                     "tar xzf \"$tmp\" --strip-components=1 --no-same-owner "
                     "-C {d}\n"
                     "rm -f \"$tmp\"\n").format(
                         url=shlex.quote(EASYRSA_URL), sha=EASYRSA_SHA256,
                         d=shlex.quote(EASYRSA_DIR)),
            undo="rm -rf {}".format(shlex.quote(EASYRSA_DIR)),
            condition=lambda: not ctx.transport.file_exists(EASYRSA_DIR + "/easyrsa"),
            timeout=300,
            why="Pinned to one release and checked against a SHA-256 we ship. "
                "If the download is tampered with, the checksum fails and we "
                "stop before it ever runs."))
        ctx.note("dir", EASYRSA_DIR, self.name)

        vars_body = self._render_easyrsa_vars(cfg)
        plan.add(Step("ovpn-easyrsa-vars", "Configure the PKI algorithm",
                      StepKind.CONFIG,
                      write=(EASYRSA_DIR + "/vars", vars_body, "0600"),
                      why="Sets {} keys for everything this CA issues.".format(
                          "ECDSA " + cfg.cert_curve if cfg.cert_type == "ecdsa"
                          else "RSA-{}".format(cfg.rsa_bits))))

        plan.add(Step(
            "ovpn-pki-init", "Initialise the PKI and build the CA", StepKind.KEY,
            command=("set -eu\n"
                     "cd {d}\n"
                     "./easyrsa init-pki\n"
                     "EASYRSA_CA_EXPIRE={ca} ./easyrsa --batch "
                     "--req-cn={cn} build-ca nopass\n"
                     "EASYRSA_CERT_EXPIRE={sd} ./easyrsa --batch "
                     "build-server-full {sn} nopass\n"
                     "EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl\n"
                     "echo {sn} > {d}/TESSERA_SERVER_NAME\n").format(
                         d=shlex.quote(EASYRSA_DIR), ca=cfg.cert_days,
                         sd=cfg.cert_days, cn=shlex.quote("Tessera CA"),
                         sn=shlex.quote(server_name)),
            undo="rm -rf {}".format(shlex.quote(PKI)),
            condition=lambda: not ctx.transport.file_exists(PKI + "/ca.crt"),
            timeout=900,
            why="Creates the certificate authority that decides which clients "
                "exist. Its private key never leaves this directory."))

        plan.add(Step(
            "ovpn-copy-certs", "Place the server certificate", StepKind.CONFIG,
            command=("set -eu\n"
                     "cd {d}\n"
                     "sn=$(cat TESSERA_SERVER_NAME)\n"
                     "cp pki/ca.crt pki/issued/\"$sn\".crt "
                     "pki/private/\"$sn\".key pki/crl.pem {s}/\n"
                     "chmod 644 {s}/crl.pem {s}/ca.crt\n"
                     "chmod 600 {s}/\"$sn\".key\n").format(
                         d=shlex.quote(EASYRSA_DIR), s=shlex.quote(SERVER_DIR)),
            why="OpenVPN drops privileges after start-up, so it reads its "
                "certificate from a directory it can still see."))

        tls_step = {
            "crypt-v2": ("openvpn --genkey tls-crypt-v2-server "
                         "{s}/tls-crypt-v2.key".format(s=SERVER_DIR)),
            "crypt": "openvpn --genkey secret {s}/tls-crypt.key".format(s=SERVER_DIR),
            "auth": "openvpn --genkey secret {s}/tls-auth.key".format(s=SERVER_DIR),
        }[cfg.tls_sig]
        plan.add(Step(
            "ovpn-tls-key", "Generate the control-channel key", StepKind.KEY,
            command="umask 077 && " + tls_step, sensitive=True,
            why="Wraps the TLS handshake itself. Without this key a scanner "
                "cannot identify the service, and cannot make the server "
                "spend CPU on a handshake."))

        # -- configuration ----------------------------------------------------
        plan.add(Step(
            "ovpn-server-conf", "Write server.conf", StepKind.CONFIG,
            command=self._render_server_conf_cmd(ctx, cfg),
            undo="rm -f {}/server.conf".format(shlex.quote(SERVER_DIR)),
            why="The server configuration, with the generated server name "
                "substituted in on the server so it always matches the cert."))
        ctx.note("file", SERVER_DIR + "/server.conf", self.name)

        # -- routing and firewall ---------------------------------------------
        if ctx.spec.hardening.ip_forward:
            fwd = "/etc/sysctl.d/99-tessera-openvpn.conf"
            was_on = ctx.transport.run(
                "test \"$(cat /proc/sys/net/ipv4/ip_forward)\" = 1").ok
            ctx.note("sysctl", "net.ipv4.ip_forward", self.name, pre_existing=was_on)
            ctx.note("file", fwd, self.name)
            plan.add(sysctl_step("net.ipv4.ip_forward", "1", f, fwd))

        plan.add(Step(
            "ovpn-firewall", "Write the firewall helper", StepKind.FIREWALL,
            write=(self._fw_path(), self._render_firewall(ctx, cfg), "0700"),
            undo="rm -f {}".format(shlex.quote(self._fw_path())),
            why="NAT and forwarding as one reversible script, recorded in the "
                "inventory so uninstall removes exactly these rules."))
        ctx.note("file", self._fw_path(), self.name)

        plan.add(Step(
            "ovpn-fw-unit", "Install the firewall unit", StepKind.FIREWALL,
            write=("/etc/systemd/system/tessera-openvpn-firewall.service",
                   self._render_fw_unit(), "0644"),
            condition=lambda: f.init == "systemd",
            why="Re-applies the rules at boot, before OpenVPN starts."))
        ctx.note("file", "/etc/systemd/system/tessera-openvpn-firewall.service",
                 self.name)
        ctx.note("service", "tessera-openvpn-firewall", self.name)

        plan.add(Step("ovpn-fw-start", "Apply firewall rules", StepKind.FIREWALL,
                      command=("systemctl daemon-reload && systemctl enable "
                               "--now tessera-openvpn-firewall"
                               if f.init == "systemd"
                               else "{} up".format(shlex.quote(self._fw_path()))),
                      undo=svc_stop_disable(f, "tessera-openvpn-firewall"),
                      critical=False))

        plan.add(Step("ovpn-open-port",
                      "Open {}/{}".format(cfg.protocol, cfg.port),
                      StepKind.FIREWALL,
                      command=open_port_cmd(f, cfg.port, cfg.protocol),
                      undo=close_port_cmd(f, cfg.port, cfg.protocol),
                      critical=False))
        ctx.note("firewall", "{}/{}".format(cfg.protocol, cfg.port), self.name)

        if f.selinux and cfg.port != 1194:
            plan.add(Step(
                "ovpn-selinux", "Allow port {} under SELinux".format(cfg.port),
                StepKind.FIREWALL,
                command="semanage port -a -t openvpn_port_t -p {pr} {p} "
                        "2>/dev/null || true".format(pr=cfg.protocol, p=cfg.port),
                undo="semanage port -d -t openvpn_port_t -p {pr} {p} "
                     "2>/dev/null || true".format(pr=cfg.protocol, p=cfg.port),
                critical=False,
                why="SELinux confines OpenVPN to its own port set; a custom "
                    "port has to be added to it or the daemon cannot bind."))

        # -- service ----------------------------------------------------------
        plan.add(Step("ovpn-start", "Enable and start openvpn-server@server",
                      StepKind.SERVICE,
                      command=svc_enable_start(f, "openvpn-server@server"),
                      undo=svc_stop_disable(f, "openvpn-server@server"),
                      timeout=120))
        ctx.note("service", "openvpn-server@server", self.name)

        plan.add(Step("ovpn-confirm", "Confirm the daemon is running",
                      StepKind.CHECK,
                      command=svc_is_active(f, "openvpn-server@server"),
                      why="A config error shows up here, not three days later."))

        plan.notes.append("Clients connect to {}:{} over {}.".format(
            cfg.endpoint or f.public_ipv4 or "<server>", cfg.port,
            cfg.protocol.upper()))
        return plan

    # ------------------------------------------------------------------ peers
    def plan_add_peer(self, ctx: EngineContext, name: str,
                      **options) -> Tuple[Plan, Peer, str]:
        cfg = ctx.spec.openvpn
        rec = ctx.state.engine(self.name)
        if rec is None:
            raise TesseraError("OpenVPN is not installed on this server",
                               "Run the installer first.")
        _validate_name(name)
        if any(p.get("name") == name and not p.get("revoked")
               for p in rec.peers):
            raise ValidationError("a peer named '{}' already exists".format(name))

        key_pem, csr_pem = generate_client_csr(
            name, curve=cfg.cert_curve, rsa_bits=cfg.rsa_bits, algo=cfg.cert_type)

        peer = Peer(name=name, engine=self.name, private_key=key_pem,
                    note=options.get("note", ""))
        remote_csr = "{}/tessera-{}.req".format(EASYRSA_DIR, name)

        plan = Plan("Add OpenVPN peer '{}'".format(name))
        plan.add(Step(
            "ovpn-upload-csr", "Upload the signing request for '{}'".format(name),
            StepKind.KEY, write=(remote_csr, csr_pem, "0600"),
            why="Only the request travels. It contains the public key and a "
                "self-signature proving we hold the private half - never the "
                "private key itself."))
        plan.add(Step(
            "ovpn-sign", "Sign the certificate for '{}'".format(name),
            StepKind.KEY,
            command=("set -eu\n"
                     "cd {d}\n"
                     "./easyrsa --batch import-req {req} {n}\n"
                     "EASYRSA_CERT_EXPIRE={days} ./easyrsa --batch "
                     "sign-req client {n}\n"
                     "rm -f {req}\n").format(
                         d=shlex.quote(EASYRSA_DIR),
                         req=shlex.quote(remote_csr), n=shlex.quote(name),
                         days=cfg.client_cert_days),
            undo=("cd {d} && ./easyrsa --batch revoke {n} 2>/dev/null; "
                  "true").format(d=shlex.quote(EASYRSA_DIR), n=shlex.quote(name)),
            timeout=180,
            why="The CA signs the request. The resulting certificate is public "
                "information; only the CA's own key had to be secret."))
        plan.notes.append(
            "The private key for '{}' was generated on this machine. The "
            "server only ever saw the signing request.".format(name))
        return plan, peer, ""

    def collect_client_config(self, ctx: EngineContext, peer: Peer) -> str:
        """Fetch the signed cert and assemble a single-file .ovpn.

        Runs after the signing plan succeeds, because it needs the artefacts
        that plan produced.
        """
        cfg = ctx.spec.openvpn
        t = ctx.transport
        f = ctx.facts
        cert = _extract_cert(t.read_file("{}/issued/{}.crt".format(PKI, peer.name)))
        ca = t.read_file(PKI + "/ca.crt").strip()

        tls_block = ""
        if cfg.tls_sig == "crypt-v2":
            r = t.run_root(
                "set -eu; tmp=$(mktemp {s}/tls-cv2.XXXXXX); "
                "openvpn --tls-crypt-v2 {s}/tls-crypt-v2.key --genkey "
                "tls-crypt-v2-client \"$tmp\" >/dev/null 2>&1; "
                "cat \"$tmp\"; rm -f \"$tmp\"".format(s=shlex.quote(SERVER_DIR)))
            tls_block = "<tls-crypt-v2>\n{}\n</tls-crypt-v2>".format(r.stdout.strip())
        elif cfg.tls_sig == "crypt":
            tls_block = "<tls-crypt>\n{}\n</tls-crypt>".format(
                t.read_file(SERVER_DIR + "/tls-crypt.key").strip())
        else:
            tls_block = "<tls-auth>\n{}\n</tls-auth>".format(
                t.read_file(SERVER_DIR + "/tls-auth.key").strip())

        server_name = t.read_file(EASYRSA_DIR + "/TESSERA_SERVER_NAME").strip()
        peer.fingerprint = cert_fingerprint(cert)
        peer.expires = cert_expiry(cert)

        endpoint = cfg.endpoint or f.public_ipv4 or f.private_ipv4
        proto = "tcp-client" if cfg.protocol == "tcp" else "udp"
        lines = [
            "# Tessera - {} @ {}".format(peer.name, peer.created),
            "client", "dev tun", "proto {}".format(proto),
            "remote {} {}".format(endpoint, cfg.port),
            "resolv-retry infinite", "nobind", "persist-key", "persist-tun",
            "remote-cert-tls server",
            "verify-x509-name {} name".format(server_name),
            "auth {}".format(cfg.auth_digest),
            "auth-nocache",
            "cipher {}".format(cfg.cipher),
            "data-ciphers {}".format(cfg.cipher),
            "tls-client",
            "tls-version-min {}".format(cfg.tls_min),
            "ignore-unknown-option block-outside-dns",
            "setenv opt block-outside-dns",
            "verb 3",
            "" if cfg.protocol == "tcp" else "explicit-exit-notify",
            "",
            "<ca>\n{}\n</ca>".format(ca),
            "<cert>\n{}\n</cert>".format(cert),
            "<key>\n{}</key>".format(peer.private_key),
            tls_block, "",
        ]
        return "\n".join(l for l in lines if l != "") + "\n"

    def plan_remove_peer(self, ctx: EngineContext, name: str) -> Plan:
        rec = ctx.state.engine(self.name)
        if rec is None:
            raise TesseraError("OpenVPN is not installed on this server")
        if not any(p.get("name") == name and not p.get("revoked")
                   for p in rec.peers):
            raise ValidationError("no active peer named '{}'".format(name))

        plan = Plan("Revoke OpenVPN peer '{}'".format(name))
        plan.add(Step(
            "ovpn-revoke", "Revoke the certificate for '{}'".format(name),
            StepKind.KEY,
            command=("set -eu\n"
                     "cd {d}\n"
                     "./easyrsa --batch revoke {n}\n"
                     "EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl\n"
                     "cp pki/crl.pem {s}/crl.pem\n"
                     "chmod 644 {s}/crl.pem\n").format(
                         d=shlex.quote(EASYRSA_DIR), n=shlex.quote(name),
                         s=shlex.quote(SERVER_DIR)),
            timeout=180,
            why="Adds the certificate to the revocation list. This is the "
                "thing WireGuard cannot do: the client's own key is now "
                "worthless even though they still hold it."))
        plan.add(Step(
            "ovpn-kill", "Disconnect '{}' if it is online".format(name),
            StepKind.SERVICE,
            command=("(command -v socat >/dev/null && printf 'kill %s\\nquit\\n' "
                     "{n} | socat - UNIX-CONNECT:/run/openvpn-server/server.sock) "
                     "2>/dev/null; true").format(n=shlex.quote(name)),
            critical=False,
            why="The CRL is only consulted on the next handshake, so an "
                "already-connected client would otherwise stay online."))
        plan.add(Step(
            "ovpn-reload-crl", "Reload the revocation list", StepKind.SERVICE,
            command="systemctl reload openvpn-server@server 2>/dev/null || "
                    "systemctl restart openvpn-server@server",
            critical=False))
        return plan

    # -------------------------------------------------------------- uninstall
    def plan_uninstall(self, ctx: EngineContext, purge: bool = True) -> Plan:
        f = ctx.facts
        plan = Plan("Remove OpenVPN")
        plan.add(Step("ovpn-un-stop", "Stop openvpn-server@server",
                      StepKind.SERVICE,
                      command=svc_stop_disable(f, "openvpn-server@server"),
                      critical=False))
        plan.add(Step("ovpn-un-fw", "Remove the firewall rules", StepKind.FIREWALL,
                      command=("systemctl disable --now "
                               "tessera-openvpn-firewall 2>/dev/null; "
                               "test -x {p} && {p} down; true").format(
                                   p=shlex.quote(self._fw_path())),
                      critical=False))
        return plan

    # ----------------------------------------------------------------- status
    def status(self, ctx: EngineContext) -> Dict[str, object]:
        f, cfg = ctx.facts, ctx.spec.openvpn
        t = ctx.transport
        active = t.run(svc_is_active(f, "openvpn-server@server")).ok
        st = t.run_root("cat /var/log/openvpn/status.log 2>/dev/null")
        return {
            "engine": self.name,
            "active": active,
            "port": cfg.port,
            "protocol": cfg.protocol,
            "peers": parse_status_log(st.stdout),
        }

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _fw_path() -> str:
        return "/etc/tessera/openvpn-firewall.sh"

    def _render_easyrsa_vars(self, cfg: OpenVPNConfig) -> str:
        if cfg.cert_type == "ecdsa":
            body = ("set_var EASYRSA_ALGO ec\n"
                    "set_var EASYRSA_CURVE {}\n".format(cfg.cert_curve))
        else:
            body = ("set_var EASYRSA_ALGO rsa\n"
                    "set_var EASYRSA_KEY_SIZE {}\n".format(cfg.rsa_bits))
        return ("# Written by Tessera.\n"
                "set_var EASYRSA_DIGEST sha512\n"
                "set_var EASYRSA_BATCH 1\n" + body)

    def _render_server_conf_cmd(self, ctx: EngineContext,
                                cfg: OpenVPNConfig) -> str:
        """Build server.conf on the server so the generated name is authoritative."""
        f = ctx.facts
        net = netcalc.parse_net(cfg.subnet_v4)
        proto = cfg.protocol
        body = [
            "# Managed by Tessera.",
            "port {}".format(cfg.port),
            "proto {}".format(proto),
            "dev tun",
            "topology subnet",
            "server {} {}".format(net.network_address, net.netmask),
            "ifconfig-pool-persist ipp.txt",
            "keepalive 10 120",
            "persist-key",
            "persist-tun",
            "user nobody",
            "group {}".format("nogroup" if f.family == "debian" else "nobody"),
            "ca ca.crt",
            "crl-verify crl.pem",
            "cert __SERVER__.crt",
            "key __SERVER__.key",
            "auth {}".format(cfg.auth_digest),
            "cipher {}".format(cfg.cipher),
            "ignore-unknown-option data-ciphers",
            "data-ciphers {}".format(cfg.cipher),
            "tls-server",
            "tls-version-min {}".format(cfg.tls_min),
            "remote-cert-tls client",
            "client-config-dir ccd",
            "status /var/log/openvpn/status.log",
            "management /run/openvpn-server/server.sock unix",
            "verb 3",
        ]
        if cfg.tls_sig == "crypt-v2":
            body.append("tls-crypt-v2 tls-crypt-v2.key")
        elif cfg.tls_sig == "crypt":
            body.append("tls-crypt tls-crypt.key")
        else:
            body.append("tls-auth tls-auth.key 0")
        if cfg.client_to_client:
            body.append("client-to-client")
        if cfg.duplicate_cn:
            body.append("duplicate-cn")
        for resolver in cfg.dns:
            body.append('push "dhcp-option DNS {}"'.format(resolver))
        body.append('push "redirect-gateway def1 bypass-dhcp"')
        if cfg.enable_ipv6 and f.has_ipv6:
            v6 = netcalc.parse_net(cfg.subnet_v6)
            body += ["server-ipv6 {}".format(v6), "tun-ipv6", "push tun-ipv6",
                     'push "redirect-gateway ipv6"']

        text = "\n".join(body) + "\n"
        return ("set -eu\n"
                "sn=$(cat {d}/TESSERA_SERVER_NAME)\n"
                "cat > {s}/server.conf <<'TESSERA_CONF'\n"
                "{text}"
                "TESSERA_CONF\n"
                "sed -i \"s/__SERVER__/$sn/g\" {s}/server.conf\n"
                "chmod 644 {s}/server.conf\n").format(
                    d=shlex.quote(EASYRSA_DIR), s=shlex.quote(SERVER_DIR),
                    text=text)

    def _render_firewall(self, ctx: EngineContext, cfg: OpenVPNConfig) -> str:
        f = ctx.facts
        nic = f.nic or "eth0"
        add4, del4 = masquerade_rules(nic, cfg.subnet_v4)
        block_up, block_down = [], []
        if ctx.spec.hardening.block_rfc1918_from_vpn:
            for net in netcalc.PROTECTED_V4:
                block_up.append(
                    "  iptables -C FORWARD -i tun+ -d {n} -j REJECT 2>/dev/null "
                    "|| iptables -I FORWARD -i tun+ -d {n} -j REJECT".format(n=net))
                block_down.append(
                    "  iptables -D FORWARD -i tun+ -d {n} -j REJECT "
                    "2>/dev/null || true".format(n=net))
        lines = [
            "#!/bin/sh", "set -u",
            "# Written by Tessera for OpenVPN. 'up' adds, 'down' removes.",
            "up() {",
            "  iptables -C INPUT -p {pr} --dport {p} -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p {pr} --dport {p} -j ACCEPT".format(
                pr=cfg.protocol, p=cfg.port),
            "  iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null || "
            "iptables -I FORWARD -i tun+ -j ACCEPT",
            "  iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null || "
            "iptables -I FORWARD -o tun+ -j ACCEPT",
        ] + block_up + ["  " + add4, "}", "", "down() {",
            "  iptables -D INPUT -p {pr} --dport {p} -j ACCEPT 2>/dev/null "
            "|| true".format(pr=cfg.protocol, p=cfg.port),
            "  iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null || true",
            "  iptables -D FORWARD -o tun+ -j ACCEPT 2>/dev/null || true",
        ] + block_down + ["  " + del4, "}", "",
            'case "${1:-}" in', "  up) up ;;", "  down) down ;;",
            '  *) echo "usage: $0 up|down" >&2; exit 2 ;;', "esac", ""]
        return "\n".join(lines)

    def _render_fw_unit(self) -> str:
        return ("[Unit]\n"
                "Description=Tessera firewall rules for OpenVPN\n"
                "After=network-online.target\n"
                "Wants=network-online.target\n"
                "Before=openvpn-server@server.service\n\n"
                "[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "ExecStart={p} up\n"
                "ExecStop={p} down\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n").format(p=self._fw_path())


# --------------------------------------------------------------------------- #
def _extract_cert(pem_bundle: str) -> str:
    """Easy-RSA writes a text dump above the PEM; keep only the certificate."""
    match = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_bundle, re.S)
    if not match:
        raise TesseraError("could not find a certificate in the signed output")
    return match.group(0)


def parse_status_log(text: str) -> List[Dict[str, object]]:
    """Parse OpenVPN's status.log CLIENT_LIST rows."""
    peers: List[Dict[str, object]] = []
    for line in text.splitlines():
        if not line.startswith("CLIENT_LIST,"):
            continue
        parts = line.split(",")
        if len(parts) < 8:
            continue
        peers.append({
            "name": parts[1],
            "real_address": parts[2],
            "virtual_address": parts[3],
            "rx_bytes": int(parts[5]) if parts[5].isdigit() else 0,
            "tx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
            "connected_since": parts[7],
        })
    return peers


def _validate_name(name: str) -> None:
    if not NAME_RE.match(name or ""):
        raise ValidationError(
            "'{}' is not a usable certificate name".format(name),
            "Use letters, digits, dot, dash and underscore; 64 chars or fewer.")

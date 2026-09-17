"""WireGuard.

Two things here differ from the reference installer, and both are deliberate.

**Client keys are generated on your desktop, not on the server.**  The upstream
script runs ``wg genkey`` on the server for each client and writes the private
key into a file in someone's home directory, where it stays forever.  Tessera
generates the pair locally and uploads only the public key.  The server is told
whom to trust and is never told the secret.

**The config file is rendered from the inventory, not edited in place.**  The
upstream script appends ``[Peer]`` blocks with ``echo >>`` and deletes them
later with a ``sed`` range.  One hand-edit, one stray blank line, and that sed
eats the wrong block.  Tessera keeps the peer list in state.json, renders the
whole file every time, and applies it with ``wg syncconf`` - which updates the
running interface *without dropping existing tunnels*.  Adding a peer does not
disconnect anyone.
"""

from __future__ import annotations

import re
import shlex
from typing import Dict, List, Tuple

from .. import netcalc
from ..errors import TesseraError, ValidationError
from ..keys import wg_keypair, wg_psk, shred_command
from ..models import Facts, Peer, WireGuardConfig
from ..plan import Plan, Step, StepKind
from .base import (Engine, EngineContext, already_installed, close_port_cmd,
                   masquerade_rules, open_port_cmd, pkg_install, pkg_refresh,
                   pkg_remove, svc_enable_start, svc_is_active,
                   svc_stop_disable, sysctl_step)

# The private key never appears on a command line.  We write the config with
# this marker and substitute it server-side from a 0600 file, using a shell
# loop rather than sed, so the key is never an argv element visible in ps.
KEY_MARKER = "__TESSERA_SERVER_KEY__"

PACKAGES = {
    "debian": ["wireguard", "wireguard-tools", "iptables", "qrencode"],
    "rhel":   ["wireguard-tools", "iptables", "qrencode"],
    "arch":   ["wireguard-tools", "iptables", "qrencode"],
    "alpine": ["wireguard-tools", "iptables", "libqrencode-tools"],
    "suse":   ["wireguard-tools", "iptables", "qrencode"],
}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,30}$")


class WireGuardEngine(Engine):
    name = "wireguard"
    label = "WireGuard"
    blurb = ("A modern tunnel in about 4,000 lines of kernel code. Fast, "
             "silent to port scanners, and reconnects instantly when you "
             "change networks.")
    strengths = (
        "Fastest of the three, and the only one in the Linux kernel",
        "Roams between Wi-Fi and mobile without dropping the tunnel",
        "Unsolicited packets get no reply at all, so scanners see nothing",
        "Config is short enough to read and understand in full",
    )
    tradeoffs = (
        "Every peer needs a fixed VPN IP, so large fleets need bookkeeping",
        "No username/password or MFA - possession of the key is the identity",
        "UDP only; blocked on networks that permit TCP 443 alone",
    )

    # ---------------------------------------------------------------- helpers
    # Every path built from the interface name goes through require_iface, so
    # a name that could escape the directory or a shell command is refused at
    # the point of use rather than trusted because of where it came from.
    @staticmethod
    def conf_path(cfg: WireGuardConfig) -> str:
        return "/etc/wireguard/{}.conf".format(
            netcalc.require_iface(cfg.interface))

    @staticmethod
    def key_path(cfg: WireGuardConfig) -> str:
        return "/etc/tessera/wg-{}.key".format(
            netcalc.require_iface(cfg.interface))

    @staticmethod
    def fw_path(cfg: WireGuardConfig) -> str:
        return "/etc/tessera/wg-{}-firewall.sh".format(
            netcalc.require_iface(cfg.interface))

    @staticmethod
    def unit(f: Facts, cfg: WireGuardConfig) -> str:
        iface = netcalc.require_iface(cfg.interface)
        if f.init == "openrc":
            return "wg-quick.{}".format(iface)
        return "wg-quick@{}".format(iface)

    # ---------------------------------------------------------------- install
    def plan_install(self, ctx: EngineContext) -> Plan:
        f, cfg = ctx.facts, ctx.spec.wireguard
        plan = Plan("Install WireGuard on {}".format(ctx.spec.target.display()))

        packages = PACKAGES.get(f.family, PACKAGES["debian"])
        # Only record packages we actually add, so uninstall never removes
        # something that was already part of the system.
        pre = {p: already_installed(ctx.transport, f, p) for p in packages}
        for p, existed in pre.items():
            ctx.note("package", p, self.name, pre_existing=existed)

        plan.add(Step("wg-refresh", "Refresh package lists", StepKind.PACKAGE,
                      command=pkg_refresh(f), critical=False,
                      why="So we install the current WireGuard, not a cached one.",
                      timeout=600))

        if f.family == "debian" and f.os_id == "debian" and f.version_id.startswith("10"):
            plan.add(Step(
                "wg-backports", "Enable Debian 10 backports", StepKind.PACKAGE,
                command=("grep -rqs 'buster-backports' /etc/apt/ || "
                         "(echo 'deb http://deb.debian.org/debian "
                         "buster-backports main' > "
                         "/etc/apt/sources.list.d/tessera-backports.list && "
                         "apt-get update -qq)"),
                undo="rm -f /etc/apt/sources.list.d/tessera-backports.list",
                why="Buster shipped before WireGuard was in the kernel."))
            ctx.note("file", "/etc/apt/sources.list.d/tessera-backports.list",
                     self.name)

        plan.add(Step("wg-packages", "Install {}".format(", ".join(packages)),
                      StepKind.PACKAGE, command=pkg_install(f, packages),
                      undo=pkg_remove(f, [p for p, e in pre.items() if not e]) or "true",
                      why="WireGuard tooling, the firewall CLI and the QR encoder.",
                      timeout=900))

        plan.add(Step("wg-verify", "Verify the wg command exists",
                      StepKind.CHECK, command="command -v wg >/dev/null",
                      why="Catches a package manager that reported success but "
                          "installed nothing usable."))

        # -- keys ------------------------------------------------------------
        plan.add(Step(
            "wg-dir", "Create /etc/wireguard and /etc/tessera", StepKind.CONFIG,
            command=("mkdir -p /etc/wireguard /etc/tessera && "
                     "chmod 700 /etc/wireguard /etc/tessera"),
            why="0700 so no other user on the box can list the key files."))
        ctx.note("dir", "/etc/wireguard", self.name)
        ctx.note("dir", "/etc/tessera", self.name)

        plan.add(Step(
            "wg-server-key", "Generate the server private key", StepKind.KEY,
            command=("umask 077 && wg genkey > {k} && chmod 600 {k}").format(
                k=shlex.quote(self.key_path(cfg))),
            undo=shred_command(self.key_path(cfg)),
            why="Redirected straight into a 0600 file, so the key is never an "
                "argument in ps output or a line in shell history.",
            sensitive=True))
        ctx.note("file", self.key_path(cfg), self.name, note="server private key")

        # -- firewall helper --------------------------------------------------
        plan.add(Step(
            "wg-firewall-script", "Write the firewall helper", StepKind.FIREWALL,
            write=(self.fw_path(cfg), self._render_firewall(f, cfg), "0700"),
            undo="rm -f {}".format(shlex.quote(self.fw_path(cfg))),
            why="Keeping NAT rules in one reviewable script - instead of a wall "
                "of PostUp lines - means the uninstaller can undo them exactly."))
        ctx.note("file", self.fw_path(cfg), self.name)

        # -- interface config -------------------------------------------------
        plan.add(Step(
            "wg-conf", "Write {}".format(self.conf_path(cfg)), StepKind.CONFIG,
            write=(self.conf_path(cfg), self.render_server_conf(ctx, []), "0600"),
            undo=shred_command(self.conf_path(cfg)),
            why="The interface definition. 0600 because it will hold preshared "
                "keys once peers are added."))
        ctx.note("file", self.conf_path(cfg), self.name)

        plan.add(self._substitute_key_step(cfg))

        # -- routing ----------------------------------------------------------
        if ctx.spec.hardening.ip_forward:
            fwd_file = "/etc/sysctl.d/99-tessera-wireguard.conf"
            forwarding_was_on = ctx.transport.run(
                "test \"$(cat /proc/sys/net/ipv4/ip_forward)\" = 1").ok
            ctx.note("sysctl", "net.ipv4.ip_forward", self.name,
                     pre_existing=forwarding_was_on)
            ctx.note("file", fwd_file, self.name)
            plan.add(sysctl_step("net.ipv4.ip_forward", "1", f, fwd_file))
            if cfg.enable_ipv6 and f.has_ipv6:
                plan.add(sysctl_step("net.ipv6.conf.all.forwarding", "1", f,
                                     fwd_file))

        add_port = open_port_cmd(f, cfg.port, "udp")
        plan.add(Step("wg-open-port", "Open UDP {}".format(cfg.port),
                      StepKind.FIREWALL, command=add_port,
                      undo=close_port_cmd(f, cfg.port, "udp"),
                      why="The one port that has to be reachable from outside.",
                      critical=False))
        ctx.note("firewall", "udp/{}".format(cfg.port), self.name)

        # -- service ----------------------------------------------------------
        unit = self.unit(f, cfg)
        if f.init == "openrc":
            plan.add(Step(
                "wg-openrc-link", "Link the OpenRC service", StepKind.SERVICE,
                command="ln -sf /etc/init.d/wg-quick /etc/init.d/{}".format(
                    shlex.quote(unit)),
                undo="rm -f /etc/init.d/{}".format(shlex.quote(unit)),
                why="OpenRC needs one init script per interface."))
            ctx.note("file", "/etc/init.d/{}".format(unit), self.name)

        plan.add(Step("wg-start", "Enable and start {}".format(unit),
                      StepKind.SERVICE, command=svc_enable_start(f, unit),
                      undo=svc_stop_disable(f, unit),
                      why="Brings the interface up now and again at boot.",
                      timeout=120))
        ctx.note("service", unit, self.name)

        plan.add(Step("wg-confirm", "Confirm the interface is up",
                      StepKind.CHECK,
                      command="wg show {} >/dev/null".format(
                          shlex.quote(cfg.interface)),
                      why="If the kernel module failed to load, we find out "
                          "here rather than when a client cannot connect."))

        plan.notes.append(
            "Clients reach this server at {}:{} over UDP.".format(
                cfg.endpoint or f.public_ipv4 or "<server address>", cfg.port))
        return plan

    def _substitute_key_step(self, cfg: WireGuardConfig) -> Step:
        """Insert the private key into the config without exposing it in argv."""
        script = (
            "set -eu\n"
            "key=$(cat {k})\n"
            "tmp=$(mktemp /etc/wireguard/.tessera.XXXXXX)\n"
            "chmod 600 \"$tmp\"\n"
            "while IFS= read -r line; do\n"
            "  if [ \"$line\" = 'PrivateKey = {m}' ]; then\n"
            "    printf 'PrivateKey = %s\\n' \"$key\"\n"
            "  else\n"
            "    printf '%s\\n' \"$line\"\n"
            "  fi\n"
            "done < {c} > \"$tmp\"\n"
            "mv -f \"$tmp\" {c}\n"
            "chmod 600 {c}\n"
        ).format(k=shlex.quote(self.key_path(cfg)), m=KEY_MARKER,
                 c=shlex.quote(self.conf_path(cfg)))
        return Step(
            "wg-inject-key", "Insert the server private key", StepKind.KEY,
            command="bash -s <<'TESSERA_EOF'\n{}\nTESSERA_EOF".format(script),
            why="Read into a shell variable rather than passed as an argument, "
                "so the key never appears in the process table.",
            sensitive=True)

    # ------------------------------------------------------------------ peers
    def plan_add_peer(self, ctx: EngineContext, name: str,
                      **options) -> Tuple[Plan, Peer, str]:
        cfg = ctx.spec.wireguard
        rec = ctx.state.engine(self.name)
        if rec is None:
            raise TesseraError("WireGuard is not installed on this server",
                               "Run the installer first.")
        _validate_name(name)
        peers = rec.peer_objects()
        if any(p.name == name and not p.revoked for p in peers):
            raise ValidationError("a peer named '{}' already exists".format(name))

        taken_v4 = [p.address_v4 for p in peers if p.address_v4]
        v4 = netcalc.allocate(cfg.subnet_v4, taken_v4 + [netcalc.server_address(cfg.subnet_v4)],
                              preferred=options.get("address_v4"))
        v6 = ""
        if cfg.enable_ipv6:
            taken_v6 = [p.address_v6 for p in peers if p.address_v6]
            v6 = netcalc.allocate(cfg.subnet_v6,
                                  taken_v6 + [netcalc.server_address(cfg.subnet_v6)])

        private, public = wg_keypair()
        peer = Peer(name=name, engine=self.name, public_key=public,
                    private_key=private, preshared_key=wg_psk(),
                    address_v4=v4, address_v6=v6,
                    interface=cfg.interface,
                    access_expires=options.get("access_expires", ""),
                    note=options.get("note", ""))

        plan = Plan("Add WireGuard peer '{}'".format(name))
        new_peers = peers + [peer]
        plan.add(Step(
            "wg-peer-conf", "Add '{}' to the server config".format(name),
            StepKind.CONFIG,
            write=(self.conf_path(cfg), self.render_server_conf(ctx, new_peers), "0600"),
            why="The whole file is rendered from the inventory, so a hand-edit "
                "cannot leave a half-deleted peer behind."))
        plan.add(self._substitute_key_step(cfg))
        plan.add(self._sync_step(cfg))
        plan.notes.append(
            "The private key for '{}' was generated on this machine and is not "
            "sent to the server.".format(name))
        return plan, peer, self.render_client_conf(ctx, peer)

    def plan_remove_peer(self, ctx: EngineContext, name: str) -> Plan:
        cfg = ctx.spec.wireguard
        rec = ctx.state.engine(self.name)
        if rec is None:
            raise TesseraError("WireGuard is not installed on this server")
        peers = rec.peer_objects()
        target = next((p for p in peers if p.name == name and not p.revoked), None)
        if target is None:
            raise ValidationError("no active peer named '{}'".format(name))

        remaining = [p for p in peers if p.name != name]
        plan = Plan("Remove WireGuard peer '{}'".format(name))
        plan.add(Step(
            "wg-peer-drop-live", "Disconnect '{}' immediately".format(name),
            StepKind.SERVICE,
            command="wg set {i} peer {k} remove".format(
                i=shlex.quote(cfg.interface), k=shlex.quote(target.public_key)),
            critical=False,
            why="Kicks the device off now. Rewriting the file alone would "
                "leave an already-connected client running until the next "
                "restart."))
        plan.add(Step(
            "wg-peer-rewrite", "Rewrite the server config", StepKind.CONFIG,
            write=(self.conf_path(cfg), self.render_server_conf(ctx, remaining), "0600"),
            why="So the peer stays gone across reboots."))
        plan.add(self._substitute_key_step(cfg))
        plan.add(self._sync_step(cfg))
        return plan

    def _sync_step(self, cfg: WireGuardConfig) -> Step:
        return Step(
            "wg-sync", "Apply the config to the live interface", StepKind.SERVICE,
            command=("wg syncconf {i} <(wg-quick strip {i})").format(
                i=shlex.quote(cfg.interface)),
            why="syncconf applies the difference. Unlike a restart, peers that "
                "did not change keep their tunnels up.",
            critical=False)

    # --------------------------------------------------------------- rendering
    def render_server_conf(self, ctx: EngineContext, peers: List[Peer]) -> str:
        f, cfg = ctx.facts, ctx.spec.wireguard
        addrs = ["{}/{}".format(netcalc.server_address(cfg.subnet_v4),
                                netcalc.prefix_len(cfg.subnet_v4))]
        if cfg.enable_ipv6 and f.has_ipv6:
            addrs.append("{}/{}".format(netcalc.server_address(cfg.subnet_v6),
                                        netcalc.prefix_len(cfg.subnet_v6)))
        fw = shlex.quote(self.fw_path(cfg))
        lines = [
            "# Managed by Tessera. Peers are rendered from /etc/tessera/state.json;",
            "# edit them with 'tessera peer add/remove' so the two stay in step.",
            "[Interface]",
            "Address = {}".format(", ".join(addrs)),
            "ListenPort = {}".format(cfg.port),
            "PrivateKey = {}".format(KEY_MARKER),
            "PostUp = {} up".format(fw),
            "PostDown = {} down".format(fw),
        ]
        if cfg.mtu:
            lines.append("MTU = {}".format(cfg.mtu))
        for p in peers:
            if p.revoked:
                continue
            allowed = [netcalc.host_cidr(p.address_v4)] if p.address_v4 else []
            if p.address_v6:
                allowed.append(netcalc.host_cidr(p.address_v6))
            lines += ["", "### tessera:peer {}".format(p.name),
                      "# added {}".format(p.created), "[Peer]",
                      "PublicKey = {}".format(p.public_key)]
            if p.preshared_key:
                lines.append("PresharedKey = {}".format(p.preshared_key))
            lines.append("AllowedIPs = {}".format(", ".join(allowed)))
        return "\n".join(lines) + "\n"

    def render_client_conf(self, ctx: EngineContext, peer: Peer) -> str:
        f, cfg = ctx.facts, ctx.spec.wireguard
        endpoint = cfg.endpoint or f.public_ipv4 or f.private_ipv4
        if ":" in endpoint and not endpoint.startswith("["):
            endpoint = "[{}]".format(endpoint)
        addrs = [netcalc.host_cidr(peer.address_v4)] if peer.address_v4 else []
        if peer.address_v6:
            addrs.append(netcalc.host_cidr(peer.address_v6))
        server_pub = ctx.state.engines.get(self.name, {}).get(
            "config", {}).get("server_public_key", "")
        lines = [
            "# Tessera - {} @ {}".format(peer.name, peer.created),
            "[Interface]",
            "PrivateKey = {}".format(peer.private_key),
            "Address = {}".format(", ".join(addrs)),
        ]
        if cfg.dns:
            lines.append("DNS = {}".format(", ".join(cfg.dns)))
        if cfg.mtu:
            lines.append("MTU = {}".format(cfg.mtu))
        lines += ["__BLANK__", "[Peer]",
                  "PublicKey = {}".format(server_pub or "<server public key>")]
        if peer.preshared_key:
            lines.append("PresharedKey = {}".format(peer.preshared_key))
        lines += [
            "Endpoint = {}:{}".format(endpoint, cfg.port),
            "AllowedIPs = {}".format(cfg.allowed_ips),
            "PersistentKeepalive = {}".format(cfg.keepalive),
        ]
        text = "\n".join(l for l in lines if l != "")
        return text.replace("__BLANK__", "") + "\n"

    def _render_firewall(self, f: Facts, cfg: WireGuardConfig) -> str:
        """NAT and forwarding rules as one auditable, reversible script."""
        nic = f.nic or "eth0"
        iface = netcalc.require_iface(cfg.interface)
        v4 = cfg.subnet_v4
        v6 = cfg.subnet_v6
        add4, del4 = masquerade_rules(nic, v4)
        add6, del6 = masquerade_rules(nic, v6, v6=True)

        block_up, block_down = [], []
        if True:  # rendered unconditionally; the caller decides via hardening
            for net in netcalc.PROTECTED_V4:
                # $IFACE, not the name inlined: the variable is assigned once
                # through shlex.quote above, so a hostile interface name
                # cannot break out of it here.
                block_up.append(
                    '  iptables -C FORWARD -i "$IFACE" -d {n} -j REJECT '
                    '2>/dev/null '
                    '|| iptables -I FORWARD -i "$IFACE" -d {n} -j REJECT'
                    .format(n=net))
                block_down.append(
                    '  iptables -D FORWARD -i "$IFACE" -d {n} -j REJECT '
                    '2>/dev/null || true'.format(n=net))

        guard = ("# Written by Tessera. Called from the interface's "
                 "PostUp/PostDown.\n"
                 "# 'up' adds the rules, 'down' removes exactly those rules.\n"
                 "# Every add is guarded with -C so running it twice is a no-op\n"
                 "# instead of stacking a duplicate rule.\n")

        parts = [
            "#!/bin/sh", "set -u", guard, "",
            "IFACE={}".format(shlex.quote(iface)),
            "NIC={}".format(shlex.quote(nic)), "",
            "up() {",
            "  iptables -C INPUT -p udp --dport {p} -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p udp --dport {p} -j ACCEPT".format(p=cfg.port),
            '  iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || '
            'iptables -I FORWARD -i "$IFACE" -j ACCEPT',
            '  iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || '
            'iptables -I FORWARD -o "$IFACE" -j ACCEPT',
        ]
        parts += ["__BLOCK_UP__"]
        parts += ["  " + add4]
        if cfg.enable_ipv6:
            parts += ["  " + add6.replace("ip6tables", "ip6tables") +
                      " 2>/dev/null || true"]
        parts += [
            "}", "",
            "down() {",
            "  iptables -D INPUT -p udp --dport {p} -j ACCEPT 2>/dev/null "
            "|| true".format(p=cfg.port),
            '  iptables -D FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || true',
            '  iptables -D FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || true',
            "__BLOCK_DOWN__",
            "  " + del4,
        ]
        if cfg.enable_ipv6:
            parts += ["  " + del6]
        parts += ["}", "",
                  'case "${1:-}" in',
                  "  up) up ;;", "  down) down ;;",
                  '  *) echo "usage: $0 up|down" >&2; exit 2 ;;',
                  "esac", ""]
        text = "\n".join(parts)
        text = text.replace("__BLOCK_UP__", "\n".join(block_up))
        text = text.replace("__BLOCK_DOWN__", "\n".join(block_down))
        return text

    # -------------------------------------------------------------- uninstall
    def plan_uninstall(self, ctx: EngineContext, purge: bool = True) -> Plan:
        f, cfg = ctx.facts, ctx.spec.wireguard
        unit = self.unit(f, cfg)
        plan = Plan("Remove WireGuard")

        plan.add(Step("wg-un-down", "Bring {} down".format(cfg.interface),
                      StepKind.SERVICE,
                      command="wg-quick down {} 2>/dev/null; true".format(
                          shlex.quote(cfg.interface)),
                      critical=False,
                      why="Runs PostDown, which removes the NAT rules the "
                          "firewall helper added."))
        plan.add(Step("wg-un-service", "Disable {}".format(unit),
                      StepKind.SERVICE, command=svc_stop_disable(f, unit),
                      critical=False, why="Stops it coming back after a reboot."))
        plan.add(Step("wg-un-fwscript", "Run the firewall helper's down path",
                      StepKind.FIREWALL,
                      command="test -x {p} && {p} down; true".format(
                          p=shlex.quote(self.fw_path(cfg))),
                      critical=False,
                      why="Belt and braces: if the interface was already down, "
                          "PostDown never ran and the rules would linger."))
        return plan

    # ----------------------------------------------------------------- status
    def status(self, ctx: EngineContext) -> Dict[str, object]:
        cfg = ctx.spec.wireguard
        t = ctx.transport
        active = t.run(svc_is_active(ctx.facts, self.unit(ctx.facts, cfg))).ok
        dump = t.run_root("wg show {} dump 2>/dev/null".format(
            shlex.quote(cfg.interface)))
        return {
            "engine": self.name,
            "active": active,
            "interface": cfg.interface,
            "port": cfg.port,
            "peers": parse_wg_dump(dump.stdout),
        }


def parse_wg_dump(text: str) -> List[Dict[str, object]]:
    """Parse ``wg show <iface> dump``.

    Tab-separated. The first line describes the interface itself; every line
    after it is a peer:
      public_key  preshared_key  endpoint  allowed_ips
      latest_handshake  rx_bytes  tx_bytes  persistent_keepalive
    """
    peers: List[Dict[str, object]] = []
    for i, line in enumerate(text.splitlines()):
        if i == 0 or not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        peers.append({
            "public_key": parts[0],
            "has_psk": parts[1] not in ("(none)", "", "0"),
            "endpoint": parts[2] if parts[2] != "(none)" else "",
            "allowed_ips": parts[3],
            "last_handshake": int(parts[4]) if parts[4].isdigit() else 0,
            "rx_bytes": int(parts[5]) if parts[5].isdigit() else 0,
            "tx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
        })
    return peers


def _validate_name(name: str) -> None:
    if not NAME_RE.match(name or ""):
        raise ValidationError(
            "'{}' is not a usable peer name".format(name),
            "Use letters, digits, dash and underscore; start with a letter or "
            "digit; 31 characters or fewer.")

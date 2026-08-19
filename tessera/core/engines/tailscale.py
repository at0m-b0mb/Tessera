"""Tailscale.

Tailscale is not the same *kind* of thing as the other two, and Tessera says so
rather than pretending all three are interchangeable.

WireGuard and OpenVPN give you a server that clients dial into: you own it end
to end, and you are responsible for the port being reachable.  Tailscale is a
mesh built on WireGuard where a **coordination server** distributes public keys
and helps peers punch through NAT.  That buys you things the other two cannot
do at all - no open inbound port, no port forwarding, devices that find each
other from behind two carrier-grade NATs, SSO with your existing identity
provider, per-device ACLs.

The trade is real and worth stating plainly: by default that coordination
server belongs to Tailscale Inc.  Your *traffic* is still end-to-end encrypted
WireGuard that they cannot read, but they do hold the key directory and the
metadata of which device talked to which.  If that is not acceptable, the same
client speaks to **Headscale**, an open-source coordination server you run
yourself, and Tessera supports pointing at one with ``login_server``.

Installation uses the official package repositories with their signing keys.
Tessera does not pipe an install script from the internet into a root shell,
which is the method Tailscale's own documentation suggests.
"""

from __future__ import annotations

import shlex
from typing import Dict, Tuple

from ..errors import TesseraError
from ..keys import shred_command
from ..models import Peer, TailscaleConfig
from ..plan import Plan, Step, StepKind
from .base import (Engine, EngineContext, pkg_install, pkg_refresh, pkg_remove,
                   svc_enable_start, svc_is_active, svc_stop_disable,
                   sysctl_step)

KEYRING = "/usr/share/keyrings/tailscale-archive-keyring.gpg"
APT_LIST = "/etc/apt/sources.list.d/tailscale.list"
YUM_REPO = "/etc/yum.repos.d/tailscale.repo"
AUTHKEY_FILE = "/etc/tessera/tailscale-authkey"


class TailscaleEngine(Engine):
    name = "tailscale"
    label = "Tailscale"
    blurb = ("A mesh network that needs no open inbound port. Devices find "
             "each other through NAT; you manage access, not routing.")
    strengths = (
        "No inbound port to open, so it works behind CGNAT and on any hotspot",
        "Every device reaches every other device directly, not via one server",
        "Log in with an existing identity provider instead of shipping keys",
        "MagicDNS gives machines names instead of addresses",
    )
    tradeoffs = (
        "Key distribution goes through a coordination server you do not own, "
        "unless you self-host Headscale",
        "The free tier caps users and devices",
        "Less useful as a plain 'route my traffic through my VPS' tunnel",
    )

    # ---------------------------------------------------------------- install
    def plan_install(self, ctx: EngineContext) -> Plan:
        f, cfg = ctx.facts, ctx.spec.tailscale
        plan = Plan("Install Tailscale on {}".format(ctx.spec.target.display()))

        ctx.note("package", "tailscale", self.name)

        if f.family == "debian":
            codename = f.version_codename or "stable"
            base = "https://pkgs.tailscale.com/stable/{}/{}".format(
                f.os_id, codename)
            plan.add(Step(
                "ts-prereq", "Install curl and gnupg", StepKind.PACKAGE,
                command=pkg_install(f, ["curl", "gnupg", "ca-certificates"]),
                critical=False, timeout=600))
            plan.add(Step(
                "ts-key", "Add Tailscale's package signing key", StepKind.CONFIG,
                command=("set -eu\n"
                         "mkdir -p /usr/share/keyrings\n"
                         "curl -fsSL --max-time 60 {b}.noarmor.gpg "
                         "-o {k}\n"
                         "chmod 644 {k}\n").format(b=base, k=shlex.quote(KEYRING)),
                undo="rm -f {}".format(shlex.quote(KEYRING)),
                why="The repository is verified against this key, so a "
                    "compromised mirror cannot serve you a modified package."))
            plan.add(Step(
                "ts-repo", "Add the Tailscale repository", StepKind.CONFIG,
                command=("curl -fsSL --max-time 60 {b}.tailscale-keyring.list "
                         "-o {l} && chmod 644 {l}").format(
                             b=base, l=shlex.quote(APT_LIST)),
                undo="rm -f {}".format(shlex.quote(APT_LIST)),
                why="Official packages, signed, and upgraded by your normal "
                    "apt upgrade - not a script that has to be re-run."))
            ctx.note("file", KEYRING, self.name)
            ctx.note("file", APT_LIST, self.name)
            ctx.note("repo", "tailscale", self.name)

        elif f.family == "rhel":
            distro = "fedora" if f.os_id == "fedora" else "centos"
            ver = "" if distro == "fedora" else "/{}".format(
                (f.version_id or "9").split(".")[0])
            url = "https://pkgs.tailscale.com/stable/{}{}/tailscale.repo".format(
                distro, ver)
            plan.add(Step(
                "ts-repo", "Add the Tailscale repository", StepKind.CONFIG,
                command=("(dnf config-manager --add-repo {u} 2>/dev/null) || "
                         "(yum-config-manager --add-repo {u}) || "
                         "curl -fsSL --max-time 60 {u} -o {r}").format(
                             u=shlex.quote(url), r=shlex.quote(YUM_REPO)),
                undo="rm -f {}".format(shlex.quote(YUM_REPO))))
            ctx.note("file", YUM_REPO, self.name)
            ctx.note("repo", "tailscale", self.name)

        plan.add(Step("ts-refresh", "Refresh package lists", StepKind.PACKAGE,
                      command=pkg_refresh(f), critical=False, timeout=600))
        plan.add(Step("ts-install", "Install tailscale", StepKind.PACKAGE,
                      command=pkg_install(f, ["tailscale"]),
                      undo=pkg_remove(f, ["tailscale"]), timeout=900))
        plan.add(Step("ts-verify", "Verify tailscale is installed",
                      StepKind.CHECK, command="command -v tailscale >/dev/null"))

        plan.add(Step("ts-daemon", "Enable and start tailscaled",
                      StepKind.SERVICE,
                      command=svc_enable_start(f, "tailscaled"),
                      undo=svc_stop_disable(f, "tailscaled"), timeout=120))
        ctx.note("service", "tailscaled", self.name)

        needs_forwarding = cfg.advertise_exit_node or bool(cfg.advertise_routes)
        if needs_forwarding:
            fwd = "/etc/sysctl.d/99-tessera-tailscale.conf"
            was_on = ctx.transport.run(
                "test \"$(cat /proc/sys/net/ipv4/ip_forward)\" = 1").ok
            ctx.note("sysctl", "net.ipv4.ip_forward", self.name, pre_existing=was_on)
            ctx.note("file", fwd, self.name)
            plan.add(sysctl_step("net.ipv4.ip_forward", "1", f, fwd))
            if f.has_ipv6:
                plan.add(sysctl_step("net.ipv6.conf.all.forwarding", "1", f, fwd))

        # -- join the network -------------------------------------------------
        if cfg.auth_key:
            plan.add(Step(
                "ts-authkey", "Stage the auth key", StepKind.KEY,
                write=(AUTHKEY_FILE, cfg.auth_key, "0600"), sensitive=True,
                why="Written to a 0600 file rather than passed on the command "
                    "line, where every user on the box could read it out of "
                    "the process table. Shredded immediately after use."))
            ctx.note("file", AUTHKEY_FILE, self.name, note="removed after use")

        plan.add(Step(
            "ts-up", "Bring Tailscale up", StepKind.SERVICE,
            command=self._up_command(cfg), timeout=180, sensitive=bool(cfg.auth_key),
            undo="tailscale down 2>/dev/null; true",
            why=("Registers this machine on your tailnet."
                 if cfg.auth_key else
                 "Without a pre-authorised key this prints a URL you must "
                 "open in a browser to approve the machine.")))

        if cfg.auth_key:
            plan.add(Step(
                "ts-shred-key", "Destroy the staged auth key", StepKind.CLEANUP,
                command=shred_command(AUTHKEY_FILE),
                why="The key is single-use or reusable depending on how you "
                    "made it; either way it has no reason to survive on disk."))

        if cfg.advertise_exit_node:
            plan.notes.append(
                "This machine offers itself as an exit node. It stays inactive "
                "until you approve it in the admin console and select it on a "
                "client.")
        if not cfg.auth_key:
            plan.notes.append(
                "No auth key was supplied: run 'tailscale up' on the server and "
                "open the URL it prints to finish joining.")
        return plan

    def _up_command(self, cfg: TailscaleConfig) -> str:
        args = ["tailscale", "up"]
        if cfg.auth_key:
            args.append("--auth-key=file:{}".format(AUTHKEY_FILE))
        if cfg.hostname:
            args.append("--hostname={}".format(shlex.quote(cfg.hostname)))
        if cfg.login_server:
            args.append("--login-server={}".format(shlex.quote(cfg.login_server)))
        if cfg.advertise_exit_node:
            args.append("--advertise-exit-node")
        if cfg.advertise_routes:
            args.append("--advertise-routes={}".format(
                ",".join(cfg.advertise_routes)))
        args.append("--accept-routes={}".format(
            "true" if cfg.accept_routes else "false"))
        args.append("--accept-dns={}".format(
            "true" if cfg.accept_dns else "false"))
        if cfg.ssh:
            args.append("--ssh")
        if cfg.shields_up:
            args.append("--shields-up")
        if cfg.unattended:
            # Survives reboots without a logged-in user to re-authenticate.
            args.append("--reset")
        cmd = " ".join(args)
        if not cfg.auth_key:
            # No key: do not block forever waiting for a browser login.
            cmd = "timeout 20 {} || true".format(cmd)
        return cmd

    # ------------------------------------------------------------------ peers
    def plan_add_peer(self, ctx: EngineContext, name: str,
                      **options) -> Tuple[Plan, Peer, str]:
        """Tailscale devices enrol themselves; there is nothing to push."""
        raise TesseraError(
            "Tailscale devices are not added from the server",
            "Install Tailscale on the device and run 'tailscale up', or "
            "generate a pre-authorised key in the admin console at "
            "https://login.tailscale.com/admin/settings/keys - then the device "
            "appears on its own.")

    def plan_remove_peer(self, ctx: EngineContext, name: str) -> Plan:
        raise TesseraError(
            "Tailscale devices are removed from the admin console",
            "Remove the machine at https://login.tailscale.com/admin/machines "
            "(or in your Headscale instance). Removing it there revokes it "
            "everywhere at once.")

    # -------------------------------------------------------------- uninstall
    def plan_uninstall(self, ctx: EngineContext, purge: bool = True) -> Plan:
        f = ctx.facts
        plan = Plan("Remove Tailscale")
        plan.add(Step(
            "ts-un-logout", "Log this machine out of the tailnet",
            StepKind.SERVICE,
            command="tailscale logout 2>/dev/null; tailscale down 2>/dev/null; true",
            critical=False,
            why="Deregisters the node so it stops appearing in your admin "
                "console as a machine that exists but never checks in."))
        plan.add(Step("ts-un-stop", "Stop tailscaled", StepKind.SERVICE,
                      command=svc_stop_disable(f, "tailscaled"), critical=False))
        plan.add(Step(
            "ts-un-state", "Remove the node's private state", StepKind.CLEANUP,
            command=("rm -rf /var/lib/tailscale 2>/dev/null; "
                     "rm -f {} 2>/dev/null; true").format(AUTHKEY_FILE),
            critical=False,
            why="/var/lib/tailscale holds this node's WireGuard private key "
                "and its tailnet credentials."))
        return plan

    # ----------------------------------------------------------------- status
    def status(self, ctx: EngineContext) -> Dict[str, object]:
        t, f = ctx.transport, ctx.facts
        active = t.run(svc_is_active(f, "tailscaled")).ok
        raw = t.run_root("tailscale status --json 2>/dev/null")
        info: Dict[str, object] = {"engine": self.name, "active": active,
                                   "peers": []}
        if raw.ok and raw.stdout.strip():
            try:
                import json
                data = json.loads(raw.stdout)
                self_node = data.get("Self") or {}
                info["hostname"] = self_node.get("HostName", "")
                info["addresses"] = self_node.get("TailscaleIPs", [])
                info["backend"] = data.get("BackendState", "")
                info["exit_node"] = bool(self_node.get("ExitNodeOption"))
                peers = []
                for node in (data.get("Peer") or {}).values():
                    peers.append({
                        "name": node.get("HostName", ""),
                        "addresses": node.get("TailscaleIPs", []),
                        "online": bool(node.get("Online")),
                        "os": node.get("OS", ""),
                        "rx_bytes": node.get("RxBytes", 0),
                        "tx_bytes": node.get("TxBytes", 0),
                    })
                info["peers"] = sorted(peers, key=lambda p: p["name"])
            except Exception:                                  # noqa: BLE001
                pass
        return info

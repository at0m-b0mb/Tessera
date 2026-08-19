"""The orchestrator.

Everything above this line is mechanism; this is the thing you actually call.
Both the CLI and the GUI drive a ``Session`` and nothing else, which is what
keeps them honest: there is no operation the GUI can perform that the CLI
cannot, because neither of them knows how to do anything on its own.

A Session owns the connection, the detected facts and the inventory, and it is
responsible for the part that is easy to get wrong: **keeping the server and
the inventory in step.**  Every mutating operation follows the same shape -
build a plan, run it, and only write the inventory once the plan actually
succeeded.  If the run fails halfway, the executor rolls back and the inventory
is never updated, so the next run does not inherit a lie about what is
installed.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Callable, Dict, List, Optional, Tuple

from .. import __version__
from . import audit as audit_mod
from . import facts as facts_mod
from . import hardening as hardening_mod
from . import state as state_mod
from . import uninstall as uninstall_mod
from .engines import get as get_engine
from .engines.base import EngineContext
from .errors import PreflightError, TesseraError
from .models import Facts, Finding, InstallSpec, Peer, Target
from .plan import Executor, ExecutionReport, Plan, ProgressHook
from .state import EngineRecord, ServerState
from .transport import LocalTransport, SSHTransport, Transport


class Session:
    """A live connection to one target, plus what we know about it."""

    def __init__(self, transport: Transport, facts: Facts,
                 state: ServerState, target: Target,
                 can_root: bool = True, state_error: str = "") -> None:
        self.transport = transport
        self.facts = facts
        self.state = state
        self.target = target
        #: False when we could not become root.  Read-only commands still work.
        self.can_root = can_root
        #: Why the inventory could not be read, if it could not.
        self.state_error = state_error

    # ------------------------------------------------------------- lifecycle
    @classmethod
    def connect(cls, target: Target, *, sudo_password: Optional[str] = None,
                resolve_public_ip: bool = True) -> "Session":
        """Open the connection and inspect the target.  Changes nothing."""
        if target.host == "demo":
            from .demo import DemoTransport, facts as demo_facts
            transport = DemoTransport()
            return cls(transport, demo_facts(),
                       ServerState(tessera_version=__version__), target,
                       can_root=True)
        if target.is_local:
            transport = LocalTransport(sudo_password=sudo_password)
        else:
            transport = SSHTransport(
                host=target.host, user=target.user or None, port=target.port,
                identity=target.identity or None, sudo_password=sudo_password)
            transport.probe()

        f = facts_mod.gather(transport, resolve_public_ip=resolve_public_ip)

        # Reading the inventory needs root, and not having it is not fatal for
        # the read-only commands.  Record why rather than guessing "not
        # installed", which would be a lie we then act on.
        can_root = transport.can_escalate()
        st, state_error = ServerState(tessera_version=__version__), ""
        if can_root:
            try:
                st = state_mod.load(transport) or st
            except TesseraError as exc:
                state_error = str(exc)
        else:
            state_error = ("not running as root, so /etc/tessera could not be "
                           "read")
        return cls(transport, f, st, target, can_root=can_root,
                   state_error=state_error)

    def require_root(self) -> None:
        """Fail early, and clearly, for anything that writes."""
        if self.can_root:
            return
        raise PreflightError(
            "root is required to change {}".format(self.target.display()),
            "Re-run with --ask-sudo-password, connect as root, run 'sudo -v' "
            "first, or grant NOPASSWD for this user.")

    def close(self) -> None:
        self.transport.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def refresh(self) -> None:
        """Re-read facts and inventory after a change."""
        self.facts = facts_mod.gather(self.transport, resolve_public_ip=False)
        self.state = (state_mod.load(self.transport)
                      or ServerState(tessera_version=__version__))

    # ------------------------------------------------------------- preflight
    def preflight(self, spec: InstallSpec) -> List[Tuple[str, str, str]]:
        """Blocking and advisory problems, checked before anything is planned."""
        issues = list(facts_mod.check_support(self.facts, spec.engines))

        # Refuse to fight over a port something else already owns.
        listening = set(facts_mod.listening_ports(self.transport))
        wanted: List[Tuple[str, int]] = []
        if "wireguard" in spec.engines:
            wanted.append(("wireguard", spec.wireguard.port))
        if "openvpn" in spec.engines:
            wanted.append(("openvpn", spec.openvpn.port))
        for engine, port in wanted:
            already_ours = engine in self.state.installed_engines
            if port in listening and not already_ours:
                issues.append(("block", engine, (
                    "port {} is already in use on this server. Choose another, "
                    "or stop whatever is listening on it.".format(port))))
        if len(wanted) == 2 and wanted[0][1] == wanted[1][1]:
            issues.append(("block", "", (
                "WireGuard and OpenVPN are both set to port {}. They cannot "
                "share it.".format(wanted[0][1]))))

        for engine in spec.engines:
            if engine in self.state.installed_engines:
                issues.append(("warn", engine, (
                    "{} is already installed here by Tessera. Re-running will "
                    "rewrite its configuration and existing peers will keep "
                    "working.".format(engine))))
            elif engine in self.facts.installed:
                issues.append(("warn", engine, (
                    "{} {} is already installed on this server but was not "
                    "installed by Tessera. Continuing will overwrite its "
                    "configuration, and the uninstaller will not know about "
                    "the parts Tessera did not create.".format(
                        engine, self.facts.installed[engine]))))
        return issues

    @staticmethod
    def blocking(issues: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
        return [i for i in issues if i[0] == "block"]

    # --------------------------------------------------------------- install
    def build_install_plan(self, spec: InstallSpec) -> Tuple[Plan, EngineContext]:
        """Compile the whole install - every engine plus hardening - into one plan."""
        ctx = EngineContext(transport=self.transport, facts=self.facts,
                            spec=spec, state=self.state)
        plan = Plan("Install on {}".format(spec.target.display() or
                                           self.target.display()))
        for name in spec.engines:
            sub = get_engine(name).plan_install(ctx)
            plan.extend(sub.steps)
            plan.notes.extend(sub.notes)
        hard = hardening_mod.plan(ctx)
        plan.extend(hard.steps)
        plan.notes.extend(hard.notes)
        return plan, ctx

    def install(self, spec: InstallSpec, *, dry_run: bool = False,
                on_progress: Optional[ProgressHook] = None,
                on_output: Optional[Callable[[str, str], None]] = None
                ) -> Tuple[ExecutionReport, Dict[str, str]]:
        """Run an install.  Returns (report, {peer_name: client_config}).

        The inventory is written only after the plan succeeds, so a failed run
        leaves no record claiming otherwise.
        """
        self.require_root()
        issues = self.preflight(spec)
        blockers = self.blocking(issues)
        if blockers:
            raise PreflightError(
                "cannot install: " + "; ".join(m for _, _, m in blockers),
                "Fix the above and try again.")

        plan, ctx = self.build_install_plan(spec)
        executor = Executor(self.transport, dry_run=dry_run,
                            on_progress=on_progress, on_output=on_output)
        report = executor.run(plan)
        if dry_run or not report.succeeded:
            return report, {}

        # Record what happened, then create the first peer.
        for name in spec.engines:
            rec = self.state.engine(name) or EngineRecord(engine=name)
            rec.config = self._engine_config_dict(spec, name)
            rec.version = self._installed_version(name)
            self.state.set_engine(rec)
        for artifact in ctx.artifacts:
            self.state.record(artifact, artifact.engine)

        if "wireguard" in spec.engines:
            pub = self._read_wg_public_key(spec)
            rec = self.state.engine("wireguard")
            rec.config["server_public_key"] = pub
            self.state.set_engine(rec)

        state_mod.save(self.transport, self.state)

        configs: Dict[str, str] = {}
        if spec.first_peer:
            for name in spec.engines:
                if name == "tailscale":
                    continue
                try:
                    _, conf = self.add_peer(name, spec.first_peer, spec=spec)
                    configs["{}:{}".format(name, spec.first_peer)] = conf
                except TesseraError:
                    continue
        return report, configs

    # ------------------------------------------------------------------ peers
    def add_peer(self, engine: str, name: str, *,
                 spec: Optional[InstallSpec] = None,
                 **options) -> Tuple[Peer, str]:
        """Create a peer.  Returns (peer, client config text)."""
        self.require_root()
        spec = spec or self.spec_from_state()
        ctx = EngineContext(transport=self.transport, facts=self.facts,
                            spec=spec, state=self.state)
        eng = get_engine(engine)
        plan, peer, client_conf = eng.plan_add_peer(ctx, name, **options)
        report = Executor(self.transport).run(plan)
        if not report.succeeded:
            raise TesseraError(
                "could not add peer '{}'".format(name),
                (report.failed_step.error if report.failed_step else ""))

        if engine == "openvpn":
            client_conf = eng.collect_client_config(ctx, peer)

        rec = self.state.engine(engine)
        stored = asdict(peer)
        # The private key is the client's, not the server's.  It is handed to
        # the caller and deliberately not written into the inventory.
        stored["private_key"] = ""
        rec.peers.append(stored)
        self.state.set_engine(rec)
        state_mod.save(self.transport, self.state)
        return peer, client_conf

    def remove_peer(self, engine: str, name: str, *,
                    spec: Optional[InstallSpec] = None) -> ExecutionReport:
        spec = spec or self.spec_from_state()
        ctx = EngineContext(transport=self.transport, facts=self.facts,
                            spec=spec, state=self.state)
        plan = get_engine(engine).plan_remove_peer(ctx, name)
        report = Executor(self.transport).run(plan)
        if not report.succeeded:
            raise TesseraError("could not remove peer '{}'".format(name))

        rec = self.state.engine(engine)
        if engine == "openvpn":
            # Certificates are revoked, not forgotten: the CRL is the record.
            for p in rec.peers:
                if p.get("name") == name:
                    p["revoked"] = True
        else:
            rec.peers = [p for p in rec.peers if p.get("name") != name]
        self.state.set_engine(rec)
        state_mod.save(self.transport, self.state)
        return report

    def list_peers(self, engine: str = "") -> List[Peer]:
        out: List[Peer] = []
        for name in ([engine] if engine else self.state.installed_engines):
            rec = self.state.engine(name)
            if rec:
                out.extend(rec.peer_objects())
        return out

    # -------------------------------------------------------------- teardown
    def build_uninstall_plan(self, engines: Optional[List[str]] = None, *,
                             purge_packages: bool = True,
                             keep_backups: bool = False,
                             remove_hardening: bool = True) -> Plan:
        ctx = EngineContext(transport=self.transport, facts=self.facts,
                            spec=self.spec_from_state(), state=self.state)
        return uninstall_mod.plan(
            ctx, engines, purge_packages=purge_packages,
            keep_backups=keep_backups, remove_hardening=remove_hardening)

    def uninstall(self, engines: Optional[List[str]] = None, *,
                  dry_run: bool = False, purge_packages: bool = True,
                  keep_backups: bool = False, remove_hardening: bool = True,
                  on_progress: Optional[ProgressHook] = None,
                  on_output: Optional[Callable[[str, str], None]] = None
                  ) -> ExecutionReport:
        self.require_root()
        plan = self.build_uninstall_plan(
            engines, purge_packages=purge_packages, keep_backups=keep_backups,
            remove_hardening=remove_hardening)
        # Rollback is meaningless here: re-creating what we just deleted would
        # leave a half-installed VPN, which is worse than a clean removal that
        # stopped early and told you where.
        executor = Executor(self.transport, dry_run=dry_run,
                            rollback_on_failure=False,
                            on_progress=on_progress, on_output=on_output)
        report = executor.run(plan)
        if dry_run:
            return report

        targets = engines if engines is not None else list(
            self.state.installed_engines)
        for name in targets:
            self.state.drop_engine(name)
        if self.state.installed_engines:
            state_mod.save(self.transport, self.state)
        return report

    # ----------------------------------------------------------------- audit
    def audit(self) -> List[Finding]:
        return audit_mod.run(self.transport, self.facts, self.state)

    def status(self) -> Dict[str, Dict]:
        spec = self.spec_from_state()
        ctx = EngineContext(transport=self.transport, facts=self.facts,
                            spec=spec, state=self.state)
        out: Dict[str, Dict] = {}
        for name in self.state.installed_engines:
            try:
                out[name] = get_engine(name).status(ctx)
            except Exception as exc:                           # noqa: BLE001
                out[name] = {"engine": name, "active": False, "error": str(exc)}
        return out

    # --------------------------------------------------------------- helpers
    def spec_from_state(self) -> InstallSpec:
        """Reconstruct the spec from the inventory, for post-install operations."""
        spec = InstallSpec(target=self.target)
        spec.engines = list(self.state.installed_engines)
        for name in spec.engines:
            rec = self.state.engine(name)
            if not rec:
                continue
            section = getattr(spec, name, None)
            if section is None:
                continue
            for key, value in (rec.config or {}).items():
                if hasattr(section, key):
                    setattr(section, key, value)
        return spec

    def _engine_config_dict(self, spec: InstallSpec, engine: str) -> Dict:
        section = getattr(spec, engine)
        data = asdict(section)
        data.pop("auth_key", None)     # never persisted
        return data

    def _installed_version(self, engine: str) -> str:
        cmds = {"wireguard": "wg --version 2>/dev/null | awk '{print $2}'",
                "openvpn": "openvpn --version 2>/dev/null | head -1 | awk '{print $2}'",
                "tailscale": "tailscale version 2>/dev/null | head -1"}
        return self.transport.run(cmds.get(engine, "true")).out

    def _read_wg_public_key(self, spec: InstallSpec) -> str:
        path = "/etc/tessera/wg-{}.key".format(spec.wireguard.interface)
        r = self.transport.run_root(
            "wg pubkey < {} 2>/dev/null".format(path))
        return r.out


# --------------------------------------------------------------------------- #
def quick_target(spec_str: str) -> Target:
    """Parse ``user@host:port`` (or ``local`` / ``demo``) into a Target."""
    s = (spec_str or "").strip()
    if s == "demo":
        return Target(host="demo", label="demo (simulated server)")
    if not s or s in ("local", "localhost", "-"):
        return Target()
    user = ""
    if "@" in s:
        user, _, s = s.partition("@")
    port = 22
    if ":" in s and not s.startswith("["):
        s, _, p = s.rpartition(":")
        if p.isdigit():
            port = int(p)
    return Target(host=s, user=user, port=port)

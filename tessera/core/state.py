"""The inventory: /etc/tessera/state.json

This file is the single reason Tessera can uninstall cleanly, and it is the
biggest functional difference from the scripts this project takes reference
from.

Their uninstall path is a fixed list written by a human: ``rm -rf
/etc/wireguard``, ``apt-get remove wireguard``, and so on.  It removes what the
author remembered on the day they wrote it.  It cannot know that *your* install
also added an nftables table, a sysctl drop-in, a systemd unit and a package
that something else on the box now depends on.  So it either leaves debris
behind or removes something you still needed.

Tessera writes down every single thing it creates, at the moment it creates it:
each file, each package, each unit, each firewall rule, each sysctl key - and,
crucially, whether that thing *already existed before we got here*.  Uninstall
then walks the inventory backwards and removes exactly the entries Tessera
added, leaving anything pre-existing alone.

Install a VPN on a box that already had iptables installed, and Tessera will
not uninstall iptables.  That is the whole point.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .errors import StateError
from .models import Peer, utcnow
from .transport import Transport

STATE_DIR = "/etc/tessera"
STATE_PATH = "/etc/tessera/state.json"
BACKUP_DIR = "/etc/tessera/backups"
STATE_VERSION = 1


@dataclass
class Artifact:
    """One thing Tessera created or changed on the server."""

    kind: str          # file | package | service | firewall | sysctl | dir | repo
    ref: str           # path, package name, unit name, rule id, sysctl key
    #: True when this already existed before Tessera ran.  Never removed.
    pre_existing: bool = False
    #: Original content, for things we modified rather than created.
    backup: str = ""
    engine: str = ""
    note: str = ""
    created: str = field(default_factory=utcnow)


@dataclass
class EngineRecord:
    """Per-engine installation record."""

    engine: str
    installed: str = field(default_factory=utcnow)
    version: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    peers: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)

    def peer_objects(self) -> List[Peer]:
        out = []
        for p in self.peers:
            known = {k: v for k, v in p.items()
                     if k in Peer.__dataclass_fields__}
            out.append(Peer(**known))
        return out


@dataclass
class ServerState:
    """The whole inventory for one server."""

    version: int = STATE_VERSION
    tessera_version: str = ""
    created: str = field(default_factory=utcnow)
    updated: str = field(default_factory=utcnow)
    engines: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    hardening: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)

    # -- engines ---------------------------------------------------------------
    def engine(self, name: str) -> Optional[EngineRecord]:
        raw = self.engines.get(name)
        if raw is None:
            return None
        return EngineRecord(
            engine=name,
            installed=raw.get("installed", ""),
            version=raw.get("version", ""),
            config=raw.get("config", {}),
            peers=raw.get("peers", []),
            artifacts=raw.get("artifacts", []))

    def set_engine(self, rec: EngineRecord) -> None:
        self.engines[rec.engine] = {
            "installed": rec.installed,
            "version": rec.version,
            "config": rec.config,
            "peers": rec.peers,
            "artifacts": rec.artifacts,
        }
        self.updated = utcnow()

    def drop_engine(self, name: str) -> None:
        self.engines.pop(name, None)
        self.updated = utcnow()

    @property
    def installed_engines(self) -> List[str]:
        return sorted(self.engines.keys())

    # -- artifacts -------------------------------------------------------------
    def record(self, artifact: Artifact, engine: str = "") -> None:
        entry = asdict(artifact)
        if engine and engine in self.engines:
            self.engines[engine].setdefault("artifacts", []).append(entry)
        else:
            self.artifacts.append(entry)
        self.updated = utcnow()

    def artifacts_for(self, engine: str) -> List[Artifact]:
        raw = self.engines.get(engine, {}).get("artifacts", [])
        return [Artifact(**{k: v for k, v in a.items()
                            if k in Artifact.__dataclass_fields__}) for a in raw]

    def all_artifacts(self) -> List[Artifact]:
        out = [Artifact(**{k: v for k, v in a.items()
                           if k in Artifact.__dataclass_fields__})
               for a in self.artifacts]
        for name in self.engines:
            out.extend(self.artifacts_for(name))
        return out

    def removable(self, engine: str = "") -> List[Artifact]:
        """Artifacts Tessera may delete: everything it created itself.

        Anything flagged ``pre_existing`` is skipped.  If iptables was already
        on the box, or IP forwarding was already on, we did not add it and we
        do not get to take it away.
        """
        pool = self.artifacts_for(engine) if engine else self.all_artifacts()
        return [a for a in pool if not a.pre_existing]

    # -- serialisation ---------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "ServerState":
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise StateError("state.json is not valid JSON", str(exc)) from exc
        if data.get("version", 0) > STATE_VERSION:
            raise StateError(
                "state.json was written by a newer Tessera "
                "(file v{}, this build understands v{})".format(
                    data.get("version"), STATE_VERSION),
                "Upgrade Tessera on this machine.")
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def load(t: Transport) -> Optional[ServerState]:
    """Read the inventory, or None if this server is not managed by Tessera."""
    if not t.file_exists(STATE_PATH):
        return None
    return ServerState.from_json(t.read_file(STATE_PATH))


def save(t: Transport, state: ServerState) -> None:
    """Write the inventory, keeping a timestamped backup of the previous one.

    Mode 0600: the file lists peer public keys and the server's configuration.
    No private keys ever go in here - see keys.py for why - but the peer list
    is still an inventory of who can reach your network, and that is not for
    every user on the box to read.
    """
    state.updated = utcnow()
    t.run_root("mkdir -p {} {} && chmod 700 {} {}".format(
        shlex.quote(STATE_DIR), shlex.quote(BACKUP_DIR),
        shlex.quote(STATE_DIR), shlex.quote(BACKUP_DIR)))
    if t.file_exists(STATE_PATH):
        stamp = utcnow().replace(":", "").replace("-", "")
        t.run_root("cp -p {} {}/state-{}.json".format(
            shlex.quote(STATE_PATH), shlex.quote(BACKUP_DIR), stamp))
        # Keep the last 20 so the directory cannot grow without bound.
        t.run_root("ls -1t {d}/state-*.json 2>/dev/null | tail -n +21 | "
                   "xargs -r rm -f".format(d=shlex.quote(BACKUP_DIR)))
    t.write_file(STATE_PATH, state.to_json(), mode="0600")


def ensure(t: Transport, tessera_version: str) -> ServerState:
    """Load the inventory, creating an empty one if this is a first install."""
    existing = load(t)
    if existing is not None:
        return existing
    return ServerState(tessera_version=tessera_version)


def summary_line(state: Optional[ServerState]) -> str:
    if state is None:
        return "not managed by Tessera"
    if not state.engines:
        return "managed by Tessera, nothing installed"
    parts = []
    for name in state.installed_engines:
        rec = state.engine(name)
        n = len([p for p in (rec.peers if rec else []) if not p.get("revoked")])
        parts.append("{} ({} peer{})".format(name, n, "" if n == 1 else "s"))
    return ", ".join(parts)

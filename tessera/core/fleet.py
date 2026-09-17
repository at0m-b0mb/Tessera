"""The server book: your machines, by name.

Typing ``root@vpn.example.com`` once is fine.  Typing it forty times, across
six commands, on three servers, is how people decide a tool is not worth it.

So Tessera keeps a small local address book.  ``tessera status prod`` resolves
``prod`` to the connection details you saved, and every command that takes a
target takes a saved name instead.

**This file holds no secrets, deliberately.**  There is no password field and
no key material - only what ``ssh`` itself would need on a command line.
Authentication stays where it belongs: in your ssh-agent, your
``~/.ssh/config``, your hardware key.  That means this file leaking is an
inconvenience (someone learns your hostnames) rather than a compromise, and it
means Tessera never has to implement credential storage, which is a thing that
is very easy to do badly.

It lives beside your other tool config - ``$XDG_CONFIG_HOME/tessera`` on Linux,
``~/Library/Application Support/Tessera`` on macOS, ``%APPDATA%\\Tessera`` on
Windows - at mode 0600, and it is plain readable JSON you can edit or check
into a private dotfiles repo.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .errors import TesseraError, ValidationError
from .models import Target, utcnow

BOOK_VERSION = 1
NAME_MAX = 40


class UnknownServer(TesseraError):
    pass


@dataclass
class Server:
    """One saved target.  Everything here is non-secret by design."""

    name: str
    host: str
    user: str = ""
    port: int = 22
    identity: str = ""           # path to a key file, not the key
    note: str = ""
    tags: List[str] = field(default_factory=list)
    added: str = field(default_factory=utcnow)
    last_seen: str = ""
    #: Cached from the last successful connection, for display without dialling.
    last_os: str = ""
    last_engines: List[str] = field(default_factory=list)

    def to_target(self) -> Target:
        return Target(host=self.host, user=self.user, port=self.port,
                      identity=self.identity, label=self.name)

    def display(self) -> str:
        who = "{}@".format(self.user) if self.user else ""
        where = "{}{}".format(who, self.host)
        if self.port != 22:
            where += ":{}".format(self.port)
        return where


@dataclass
class Book:
    version: int = BOOK_VERSION
    servers: Dict[str, Dict] = field(default_factory=dict)

    # -- access ---------------------------------------------------------------
    def get(self, name: str) -> Optional[Server]:
        raw = self.servers.get(name)
        if raw is None:
            return None
        known = {k: v for k, v in raw.items() if k in Server.__dataclass_fields__}
        return Server(**known)

    def all(self) -> List[Server]:
        out = [self.get(n) for n in sorted(self.servers)]
        return [s for s in out if s is not None]

    def put(self, server: Server) -> None:
        self.servers[server.name] = asdict(server)

    def drop(self, name: str) -> bool:
        return self.servers.pop(name, None) is not None

    def names(self) -> List[str]:
        return sorted(self.servers)

    # -- serialisation --------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "Book":
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise TesseraError("the server book is not valid JSON",
                               "{}  ({})".format(exc, path()))
        if data.get("version", 0) > BOOK_VERSION:
            raise TesseraError(
                "the server book was written by a newer Tessera",
                "Upgrade Tessera on this machine.")
        return cls(version=data.get("version", BOOK_VERSION),
                   servers=data.get("servers", {}))


# --------------------------------------------------------------------------- #
# Location
# --------------------------------------------------------------------------- #
def config_dir() -> str:
    """Where this platform expects a CLI tool to keep its configuration."""
    override = os.environ.get("TESSERA_CONFIG_DIR")
    if override:
        return override
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "Tessera")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Tessera")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "tessera")


def path() -> str:
    return os.path.join(config_dir(), "servers.json")


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def load() -> Book:
    p = path()
    if not os.path.exists(p):
        return Book()
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return Book.from_json(fh.read())
    except OSError as exc:
        raise TesseraError("cannot read the server book",
                           "{}: {}".format(p, exc))


def save(book: Book) -> None:
    """Write atomically at 0600.

    Atomically because a half-written book on a laptop that lost power is a
    person who has lost the addresses of all their servers.  0600 because the
    hostnames of your infrastructure are not for every account on the machine.
    """
    d = config_dir()
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass                      # best effort; Windows ACLs do not map cleanly
    final = path()
    tmp = final + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(book.to_json())
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, final)


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #
def validate_name(name: str) -> None:
    if not name:
        raise ValidationError("a server needs a name")
    if len(name) > NAME_MAX:
        raise ValidationError(
            "'{}' is too long ({} characters, max {})".format(
                name, len(name), NAME_MAX))
    if "@" in name or ":" in name or "/" in name:
        raise ValidationError(
            "'{}' cannot be used as a nickname".format(name),
            "Nicknames must not contain @ : or /, because those are how "
            "Tessera tells a nickname apart from a user@host:port target.")
    if name in ("local", "localhost", "demo", "-"):
        raise ValidationError(
            "'{}' is reserved".format(name),
            "That word already means something to Tessera: 'local' is this "
            "machine and 'demo' is the simulated server.")


def add(name: str, target: str, *, note: str = "", tags: Optional[List[str]] = None,
        identity: str = "", overwrite: bool = False) -> Server:
    from .manager import quick_target
    validate_name(name)
    book = load()
    if name in book.servers and not overwrite:
        raise ValidationError(
            "a server called '{}' is already saved".format(name),
            "Use --force to replace it, or pick another name.")
    t = quick_target(target)
    if t.is_local or t.host == "demo":
        raise ValidationError(
            "'{}' is not a remote target".format(target),
            "The server book is for machines you reach over SSH. 'local' and "
            "'demo' already work without being saved.")
    server = Server(name=name, host=t.host, user=t.user, port=t.port,
                    identity=identity or t.identity, note=note,
                    tags=list(tags or []))
    book.put(server)
    save(book)
    return server


def remove(name: str) -> None:
    book = load()
    if not book.drop(name):
        raise UnknownServer(
            "no saved server called '{}'".format(name),
            _did_you_mean(name, book.names()))
    save(book)


def touch(name: str, *, os_summary: str = "",
          engines: Optional[List[str]] = None) -> None:
    """Record a successful connection.  Failure here is never fatal."""
    try:
        book = load()
        server = book.get(name)
        if server is None:
            return
        server.last_seen = utcnow()
        if os_summary:
            server.last_os = os_summary
        if engines is not None:
            server.last_engines = list(engines)
        book.put(server)
        save(book)
    except Exception:                                          # noqa: BLE001
        # A read-only config dir must not break an otherwise working command.
        pass


def resolve(value: str) -> Target:
    """Turn a saved nickname *or* a raw target into a Target.

    Saved names win.  A nickname cannot contain ``@``, ``:`` or ``/``, so there
    is no case where a real ``user@host`` is mistaken for a nickname or the
    reverse - the two namespaces cannot overlap.
    """
    from .manager import quick_target
    value = (value or "").strip()
    if not value or value in ("local", "localhost", "-", "demo"):
        return quick_target(value)
    if "@" not in value and ":" not in value and "/" not in value:
        book = load()
        server = book.get(value)
        if server is not None:
            return server.to_target()
        # Looks like a nickname but is not saved.  If it could be a hostname,
        # let it through; otherwise say so rather than failing at DNS.
        if "." not in value:
            raise UnknownServer(
                "no saved server called '{}'".format(value),
                _did_you_mean(value, book.names()) or
                "Save it with: tessera servers add {} user@host".format(value))
    return quick_target(value)


def _did_you_mean(name: str, candidates: List[str]) -> str:
    if not candidates:
        return "No servers are saved yet. Add one with 'tessera servers add'."
    import difflib
    close = difflib.get_close_matches(name, candidates, n=3, cutoff=0.5)
    if close:
        return "Did you mean: {}?".format(", ".join(close))
    return "Saved servers: {}".format(", ".join(candidates))

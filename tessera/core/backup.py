"""Encrypted backup, restore and migration.

A VPN server is a small amount of state that is very expensive to lose. The
CA private key, the server's WireGuard key and the peer list are what make
every client config in the world still work. Lose them and the recovery is not
"restore from backup", it is "reissue credentials to every person and device",
which for most people means the VPN is simply gone.

So this pulls all of it into one file you can put somewhere safe, and pushes it
back onto a new machine with the keys intact - which means existing clients
keep connecting to the new host without being touched.

**The archive is always encrypted, and there is no flag to turn that off.**
It contains the certificate authority's private key. A plaintext copy of that
sitting in a Downloads folder or a cloud sync directory is worse than having no
backup, because it converts a storage problem into a compromise. The passphrase
is stretched with scrypt (N=2^15) and the payload sealed with AES-256-GCM, so
the file is both unreadable and tamper-evident: a single flipped byte makes the
authentication tag fail and the restore refuses rather than writing you a
subtly corrupted PKI.

The format is deliberately boring and documented, so this is never the thing
that stops you recovering:

    TESSERA-BACKUP-1\\n
    {"kdf": "scrypt", "n": 32768, "r": 8, "p": 1,
     "salt": "<base64>", "nonce": "<base64>", "created": "..."}\\n
    <AES-256-GCM ciphertext>

The plaintext inside is a gzipped tar of the server's Tessera-managed files
plus a JSON manifest. If Tessera ever stops working, ``openssl`` and ``tar``
will get your data out.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .errors import TesseraError, ValidationError
from .models import utcnow
from .state import ServerState
from .transport import Transport

MAGIC = b"TESSERA-BACKUP-1"
SCRYPT_N = 1 << 15          # ~32 MB, ~100 ms. Painful to brute force, fine to wait for.
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
MAX_ARCHIVE = 64 * 1024 * 1024

#: What is worth keeping. Globs are expanded on the server.
PATHS = [
    "/etc/tessera",
    "/etc/wireguard",
    "/etc/openvpn/server",
]


class BackupError(TesseraError):
    pass


class WrongPassphrase(BackupError):
    def __init__(self) -> None:
        super().__init__(
            "the passphrase is wrong, or the file has been altered",
            "AES-GCM cannot tell those two apart on purpose. If you are sure "
            "of the passphrase, the file is damaged - try another copy.")


@dataclass
class Manifest:
    """What is in the archive, readable before you decide to restore it."""

    created: str = field(default_factory=utcnow)
    tessera_version: str = ""
    server: str = ""
    os_summary: str = ""
    engines: List[str] = field(default_factory=list)
    peer_count: int = 0
    paths: List[str] = field(default_factory=list)
    bytes_uncompressed: int = 0

    def summary(self) -> str:
        return "{} · {} · {} peer{} · taken {}".format(
            self.server or "unknown server",
            ", ".join(self.engines) or "no engines",
            self.peer_count, "" if self.peer_count == 1 else "s",
            self.created[:10])


# --------------------------------------------------------------------------- #
# Crypto
# --------------------------------------------------------------------------- #
def _derive(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValidationError("a passphrase is required")
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise BackupError(
            "the 'cryptography' package is required for backups",
            "pip install cryptography")
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def seal(plaintext: bytes, passphrase: str, manifest: Manifest) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive(passphrase, salt)
    header = {
        "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "manifest": {
            "created": manifest.created,
            "tessera_version": manifest.tessera_version,
            "server": manifest.server,
            "os_summary": manifest.os_summary,
            "engines": manifest.engines,
            "peer_count": manifest.peer_count,
            "paths": manifest.paths,
            "bytes_uncompressed": manifest.bytes_uncompressed,
        },
    }
    header_bytes = json.dumps(header, sort_keys=True).encode()
    # The header is authenticated as associated data, so nobody can edit the
    # manifest - or downgrade the KDF parameters - without the tag failing.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header_bytes)
    return MAGIC + b"\n" + header_bytes + b"\n" + ciphertext


def peek(blob: bytes) -> Manifest:
    """Read the manifest without the passphrase.  It is not secret."""
    header, _ = _split(blob)
    m = header.get("manifest", {})
    known = {k: v for k, v in m.items() if k in Manifest.__dataclass_fields__}
    return Manifest(**known)


def unseal(blob: bytes, passphrase: str) -> Tuple[bytes, Manifest]:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    header, ciphertext = _split(blob)
    try:
        salt = base64.b64decode(header["salt"])
        nonce = base64.b64decode(header["nonce"])
        n = int(header.get("n", SCRYPT_N))
        r = int(header.get("r", SCRYPT_R))
        p = int(header.get("p", SCRYPT_P))
    except (KeyError, ValueError) as exc:
        raise BackupError("the backup header is malformed", str(exc))

    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    key = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p).derive(
        passphrase.encode("utf-8"))
    header_bytes = json.dumps(header, sort_keys=True).encode()
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header_bytes)
    except InvalidTag:
        raise WrongPassphrase()
    return plaintext, peek(blob)


def _split(blob: bytes) -> Tuple[Dict, bytes]:
    if not blob.startswith(MAGIC):
        raise BackupError(
            "this is not a Tessera backup",
            "The file should start with {}.".format(MAGIC.decode()))
    try:
        rest = blob[len(MAGIC) + 1:]
        header_bytes, _, ciphertext = rest.partition(b"\n")
        return json.loads(header_bytes.decode()), ciphertext
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackupError("the backup header is unreadable", str(exc))


# --------------------------------------------------------------------------- #
# Capture
# --------------------------------------------------------------------------- #
def capture(t: Transport, state: ServerState, *, server_label: str,
            os_summary: str, tessera_version: str) -> Tuple[bytes, Manifest]:
    """Pull the server's Tessera-managed files into an in-memory tarball."""
    present: List[str] = []
    for path in PATHS:
        if t.file_exists(path):
            present.append(path)
    if not present:
        raise BackupError(
            "nothing to back up on this server",
            "No Tessera-managed directories were found.")

    quoted = " ".join(shlex.quote(p) for p in present)
    # Tar on the server, base64 over the wire: one round trip, and the transport
    # only ever carries text, which keeps it working over plain ssh.
    res = t.run_root(
        "tar czf - --absolute-names {} 2>/dev/null | base64 | tr -d '\\n'"
        .format(quoted), timeout=600)
    if not res.ok or not res.stdout.strip():
        raise BackupError("could not read the server's configuration",
                          (res.stderr or "").strip())
    try:
        payload = base64.b64decode(res.stdout.strip(), validate=True)
    except Exception as exc:                                   # noqa: BLE001
        raise BackupError("the archive came back corrupted", str(exc))
    if len(payload) > MAX_ARCHIVE:
        raise BackupError(
            "the archive is {:.0f} MB, which is larger than expected".format(
                len(payload) / 1e6),
            "Something unusual is in /etc/openvpn or /etc/wireguard. Check "
            "before backing it up.")

    manifest = Manifest(
        tessera_version=tessera_version, server=server_label,
        os_summary=os_summary, engines=list(state.installed_engines),
        peer_count=sum(len(state.engine(e).peers)
                       for e in state.installed_engines
                       if state.engine(e)),
        paths=present, bytes_uncompressed=len(payload))
    return payload, manifest


def write(path: str, blob: bytes) -> None:
    """Write the archive at 0600, created with that mode rather than chmod-ed."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)


def read(path: str) -> bytes:
    if not os.path.exists(path):
        raise BackupError("no such file: {}".format(path))
    with open(path, "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #
def contents(payload: bytes) -> List[str]:
    """List the archive's members without extracting anything."""
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        return tar.getnames()


def inspect(payload: bytes) -> Tuple[List[str], List[str]]:
    """What a restore would write, and what it would refuse.

    Shown before any confirmation prompt, so "this archive wanted to write to
    /root/.ssh/authorized_keys" is something you find out before typing
    RESTORE, not afterwards.
    """
    clean, rejected = sanitise(payload)
    return contents(clean), rejected


def restore_plan_paths(payload: bytes) -> List[str]:
    """Top-level directories the restore would overwrite."""
    tops = set()
    for name in contents(payload):
        clean = name.lstrip("/")
        parts = clean.split("/")
        if len(parts) >= 2:
            tops.add("/" + "/".join(parts[:2]))
    return sorted(tops)


class UnsafeArchive(BackupError):
    pass


#: Restore may only write inside these. A backup has no legitimate reason to
#: place a file anywhere else, and an archive that tries is hostile.
ALLOWED_PREFIXES = ("etc/tessera/", "etc/wireguard/", "etc/openvpn/")


def sanitise(payload: bytes) -> Tuple[bytes, List[str]]:
    """Validate an archive and re-pack it with safe, relative paths.

    A backup is data from outside the program, and restore unpacks it **as
    root**. Handing that straight to ``tar`` is an arbitrary file write: an
    archive containing ``/etc/cron.d/x`` or ``/root/.ssh/authorized_keys``
    would simply be obeyed, and the encryption does not help, because the
    attacker is whoever hands you the file and the passphrase to go with it.

    So nothing reaches the server until it has been checked here:

      * **Only regular files and directories.** A symlink member is how you
        turn "write into /etc/wireguard" into "write into /root": tar creates
        ``/etc/wireguard/evil -> /root/.ssh`` and the next member writes
        through it. Hardlinks and device nodes are refused for the same reason.
      * **Only paths under the directories Tessera owns.** Checked after
        normalising, so ``etc/tessera/../../root`` is caught rather than being
        cleaned up into something that passes.
      * **Relative paths only**, so the extraction cannot be steered by a
        leading slash even if the tar flags were ever changed again.

    Returns (clean archive, list of rejected members).
    """
    import io
    import posixpath
    import tarfile

    rejected: List[str] = []
    out = io.BytesIO()
    try:
        src = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
    except tarfile.TarError as exc:
        raise UnsafeArchive("the archive is not a readable tarball", str(exc))

    with src, tarfile.open(fileobj=out, mode="w:gz") as dst:
        for member in src.getmembers():
            if not (member.isfile() or member.isdir()):
                rejected.append("{} ({})".format(
                    member.name,
                    "symlink" if member.issym() else
                    "hardlink" if member.islnk() else "special file"))
                continue

            relative = member.name.lstrip("/")
            normalised = posixpath.normpath(relative)
            if normalised.startswith("..") or posixpath.isabs(normalised):
                rejected.append("{} (escapes the restore root)".format(member.name))
                continue
            if not any(normalised.startswith(prefix) or
                       normalised == prefix.rstrip("/")
                       for prefix in ALLOWED_PREFIXES):
                rejected.append("{} (outside {})".format(
                    member.name, " ".join(ALLOWED_PREFIXES)))
                continue

            clean = tarfile.TarInfo(normalised)
            clean.type = member.type
            clean.size = member.size if member.isfile() else 0
            clean.mtime = member.mtime
            # Never carry ownership or setuid/setgid bits across machines.
            clean.mode = (member.mode & 0o777) & ~0o022
            clean.uid = clean.gid = 0
            clean.uname = clean.gname = "root"
            if member.isdir():
                dst.addfile(clean)
            else:
                extracted = src.extractfile(member)
                if extracted is None:
                    rejected.append("{} (unreadable)".format(member.name))
                    continue
                dst.addfile(clean, extracted)

    return out.getvalue(), rejected


def push(t: Transport, payload: bytes, *, dry_run: bool = False) -> List[str]:
    """Unpack the archive onto the target.  Returns the members it refused.

    The payload is sanitised first (see ``sanitise``), so what reaches the
    server contains only relative paths under the directories Tessera owns.
    """
    clean, rejected = sanitise(payload)
    if dry_run:
        return rejected

    encoded = base64.b64encode(clean).decode()
    # Staged through mktemp inside a root-only directory. The previous fixed
    # path in /tmp was a symlink attack: any local user could pre-create
    # /tmp/tessera-restore.tgz pointing at a file they wanted overwritten, and
    # this runs as root.
    script = (
        "set -eu\n"
        "umask 077\n"
        "mkdir -p /etc/tessera && chmod 700 /etc/tessera\n"
        "staged=$(mktemp /etc/tessera/.restore.XXXXXX)\n"
        "trap 'rm -f \"$staged\"' EXIT INT TERM\n"
        "base64 -d > \"$staged\"\n"
        "tar tzf \"$staged\" >/dev/null\n"
        "tar xzf \"$staged\" -C / --no-same-owner --no-same-permissions\n"
        "chmod 700 /etc/tessera /etc/wireguard 2>/dev/null || true\n"
        "chmod 600 /etc/tessera/*.json /etc/tessera/*.key "
        "/etc/wireguard/*.conf 2>/dev/null || true\n"
        "chmod 700 /etc/tessera/*.sh 2>/dev/null || true\n"
    )
    res = t.run_root(script, input_text=encoded, timeout=600)
    if not res.ok:
        raise BackupError("restore failed on the server",
                          (res.stderr or res.stdout or "").strip()[:500])
    return rejected


def rewrite_endpoint(state: ServerState, new_endpoint: str) -> List[str]:
    """Point a restored inventory at its new host.

    Migrating keeps the keys, so existing clients still authenticate - but they
    are still dialling the old address. This updates the inventory; the CLI
    tells you plainly that the client configs themselves need the new endpoint
    too, because we cannot reach out and edit files on other people's laptops.
    """
    changed = []
    for name in state.installed_engines:
        rec = state.engine(name)
        if rec and rec.config.get("endpoint") and rec.config["endpoint"] != new_endpoint:
            changed.append("{}: {} -> {}".format(
                name, rec.config["endpoint"], new_endpoint))
            rec.config["endpoint"] = new_endpoint
            state.set_engine(rec)
    return changed

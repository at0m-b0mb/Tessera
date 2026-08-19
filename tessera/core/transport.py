"""How Tessera reaches the machine it is configuring.

Tessera never assumes it is running *on* the VPN server.  Every command goes
through a Transport, and there are two:

  LocalTransport  - you are already on the Linux box (or in its container).
  SSHTransport    - the box is somewhere else.

SSHTransport shells out to the system ``ssh`` binary rather than embedding a
Python SSH library.  That is a deliberate trade:

  * ``ssh`` exists on macOS, on every Linux, and on Windows 10+ (OpenSSH is a
    shipped optional feature, on by default since 1809).  So "works on any OS"
    costs us zero dependencies.
  * It reads ``~/.ssh/config``, so ``Host prod`` aliases, ProxyJump bastions,
    per-host keys and port overrides all work with no code from us.
  * It uses the running ssh-agent, so hardware keys (YubiKey, Secure Enclave,
    FIDO ``sk-`` keys) work.  A Python library would have to reimplement that.
  * Host key verification is OpenSSH's, against your real ``known_hosts``.  We
    do not get to accidentally write a "just trust it" code path, because we
    never implement trust at all.

The cost is that we cannot hold a persistent channel open as cheaply, which we
buy back with ControlMaster multiplexing: the first command opens a connection,
the rest reuse it over a socket, so a 40-step install is one TCP handshake and
one authentication.
"""

from __future__ import annotations

import getpass
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from .errors import AuthError, TransportError

# A sink for live output lines: fn(stream, text) where stream is "out"/"err".
OutputSink = Callable[[str, str], None]


@dataclass
class CommandResult:
    """Outcome of one command.  Never raises on its own; callers decide."""

    command: str
    code: int
    stdout: str
    stderr: str
    duration: float

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def out(self) -> str:
        """stdout stripped of the trailing newline - the common case."""
        return self.stdout.strip()


class Transport:
    """Interface shared by local and remote execution."""

    #: Human label shown in the UI, e.g. "root@vpn.example.com".
    label: str = "unknown"
    #: True when commands already run with uid 0 and need no escalation.
    is_root: bool = False

    def run(self, command: str, *, check: bool = False, timeout: int = 300,
            sink: Optional[OutputSink] = None,
            input_text: Optional[str] = None) -> CommandResult:
        raise NotImplementedError

    def run_root(self, command: str, **kw) -> CommandResult:
        """Run a command with root privileges, escalating if needed."""
        raise NotImplementedError

    def read_file(self, path: str) -> str:
        r = self.run_root("cat -- {}".format(shlex.quote(path)))
        if not r.ok:
            raise TransportError("cannot read {}".format(path), r.stderr.strip())
        return r.stdout

    def write_file(self, path: str, content: str, mode: str = "0600") -> None:
        """Write a file atomically, without ever putting content on a command line.

        Content goes over stdin via a random heredoc delimiter, so secrets never
        appear in ``ps`` output, in the shell history, or in sudo's audit log.
        We write to a temp file in the same directory and rename, so a crash or
        a dropped connection can never leave a half-written key on disk.
        """
        delim = "TESSERA_{}".format(uuid.uuid4().hex.upper())
        q = shlex.quote(path)
        script = (
            "set -eu\n"
            "d=$(dirname -- {q}); mkdir -p -- \"$d\"\n"
            "t=$(mktemp \"$d/.tessera.XXXXXX\")\n"
            "chmod {mode} \"$t\"\n"
            "cat > \"$t\" <<'{delim}'\n"
            "{content}\n"
            "{delim}\n"
            "mv -f \"$t\" {q}\n"
            "chmod {mode} {q}\n"
        ).format(q=q, mode=mode, delim=delim, content=content.rstrip("\n"))
        r = self.run_root("bash -s", input_text=script)
        if not r.ok:
            raise TransportError(
                "cannot write {}".format(path), r.stderr.strip())

    def file_exists(self, path: str) -> bool:
        """True if the path exists.  Never raises.

        Tries unprivileged first: most paths are visible without root, and
        asking for root on every existence check would prompt for a password
        during read-only inspection.
        """
        q = shlex.quote(path)
        if self.run("test -e {}".format(q)).ok:
            return True
        try:
            return self.run_root("test -e {}".format(q)).ok
        except Exception:                                      # noqa: BLE001
            return False

    def which(self, binary: str) -> Optional[str]:
        r = self.run("command -v {}".format(shlex.quote(binary)))
        return r.out if r.ok and r.out else None

    def can_escalate(self) -> bool:
        """Can we obtain root here, right now, without prompting?

        Deliberately non-raising: read-only commands such as ``doctor`` must be
        able to report "I cannot see /etc/tessera because I am not root" rather
        than aborting.  Only the commands that actually need to write should
        treat the absence of root as fatal.
        """
        if self.is_root:
            return True
        try:
            return self.run("sudo -n true 2>/dev/null", timeout=15).ok
        except Exception:                                      # noqa: BLE001
            return False

    def close(self) -> None:
        pass

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class LocalTransport(Transport):
    """Run commands on this machine."""

    def __init__(self, sudo_password: Optional[str] = None) -> None:
        self.label = "{}@localhost".format(getpass.getuser())
        self.is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        self._sudo_password = sudo_password

    def run(self, command: str, *, check: bool = False, timeout: int = 300,
            sink: Optional[OutputSink] = None,
            input_text: Optional[str] = None) -> CommandResult:
        return _spawn(["bash", "-c", command], command, timeout, sink, input_text)

    def run_root(self, command: str, **kw) -> CommandResult:
        if self.is_root:
            return self.run(command, **kw)
        if shutil.which("sudo") is None:
            raise AuthError(
                "root privileges required but sudo is not installed",
                "Run Tessera as root, or install sudo.")
        # -S reads the password from stdin; -p '' suppresses the prompt so it
        # cannot be confused with the command's own output.
        inp = kw.pop("input_text", None)
        if self._sudo_password is not None:
            payload = self._sudo_password + "\n" + (inp or "")
            wrapped = "sudo -S -p '' bash -c {}".format(shlex.quote(command))
            return self.run(wrapped, input_text=payload, **kw)
        wrapped = "sudo -n bash -c {}".format(shlex.quote(command))
        r = self.run(wrapped, input_text=inp, **kw)
        if r.code != 0 and "password is required" in r.stderr:
            raise AuthError(
                "sudo needs a password and none was supplied",
                "Provide the sudo password, or run 'sudo -v' first.")
        return r


class SSHTransport(Transport):
    """Run commands on a remote machine over the system ssh binary."""

    def __init__(self, host: str, user: Optional[str] = None,
                 port: int = 22, identity: Optional[str] = None,
                 sudo_password: Optional[str] = None,
                 extra_opts: Optional[Sequence[str]] = None,
                 connect_timeout: int = 15,
                 multiplex: bool = True) -> None:
        if shutil.which("ssh") is None:
            raise TransportError(
                "no ssh client found on this machine",
                "macOS and Linux ship one.  On Windows enable "
                "'OpenSSH Client' under Settings > Apps > Optional Features.")
        self.host = host
        self.user = user
        self.port = port
        self.identity = identity
        self.extra_opts = list(extra_opts or [])
        self.connect_timeout = connect_timeout
        self._sudo_password = sudo_password
        self._ctl_dir: Optional[str] = None
        self._ctl_path: Optional[str] = None
        self.label = "{}{}{}".format(
            (user + "@") if user else "", host,
            ":{}".format(port) if port != 22 else "")
        if multiplex:
            self._ctl_dir = tempfile.mkdtemp(prefix="tessera-ssh-")
            # Short path: the control socket lives inside a sockaddr_un, which
            # caps at ~104 bytes on macOS.  A long TMPDIR plus a long hostname
            # silently breaks multiplexing, so keep the filename tiny.
            self._ctl_path = os.path.join(self._ctl_dir, "c")

    # -- command construction -------------------------------------------------
    def _base_args(self) -> List[str]:
        args = ["ssh", "-p", str(self.port),
                "-o", "ConnectTimeout={}".format(self.connect_timeout),
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new"]
        if self._ctl_path:
            args += ["-o", "ControlMaster=auto",
                     "-o", "ControlPath={}".format(self._ctl_path),
                     "-o", "ControlPersist=120"]
        if self.identity:
            args += ["-i", self.identity, "-o", "IdentitiesOnly=yes"]
        for opt in self.extra_opts:
            args += ["-o", opt]
        args.append("{}{}".format((self.user + "@") if self.user else "", self.host))
        return args

    def run(self, command: str, *, check: bool = False, timeout: int = 300,
            sink: Optional[OutputSink] = None,
            input_text: Optional[str] = None) -> CommandResult:
        argv = self._base_args() + ["bash -c {}".format(shlex.quote(command))]
        res = _spawn(argv, command, timeout, sink, input_text)
        if res.code == 255 and not res.stdout:
            _raise_ssh_failure(self.label, res.stderr)
        return res

    def run_root(self, command: str, **kw) -> CommandResult:
        if self.is_root:
            return self.run(command, **kw)
        inp = kw.pop("input_text", None)
        if self._sudo_password is not None:
            payload = self._sudo_password + "\n" + (inp or "")
            return self.run("sudo -S -p '' bash -c {}".format(shlex.quote(command)),
                            input_text=payload, **kw)
        r = self.run("sudo -n bash -c {}".format(shlex.quote(command)),
                     input_text=inp, **kw)
        if r.code != 0 and ("password is required" in r.stderr
                            or "a terminal is required" in r.stderr):
            raise AuthError(
                "passwordless sudo is not available for {}".format(self.label),
                "Supply the sudo password, connect as root, or grant NOPASSWD.")
        return r

    def probe(self) -> None:
        """Open the connection early so auth errors surface before any work."""
        r = self.run("echo tessera-ok", timeout=self.connect_timeout + 10)
        if not r.ok or "tessera-ok" not in r.stdout:
            _raise_ssh_failure(self.label, r.stderr or r.stdout)
        self.is_root = self.run("id -u").out == "0"

    def close(self) -> None:
        if self._ctl_path and os.path.exists(self._ctl_path):
            subprocess.run(self._base_args()[:-1] + ["-O", "exit", self.host],
                           capture_output=True)
        if self._ctl_dir and os.path.isdir(self._ctl_dir):
            shutil.rmtree(self._ctl_dir, ignore_errors=True)
        self._ctl_dir = self._ctl_path = None


def _raise_ssh_failure(label: str, stderr: str) -> None:
    """Turn OpenSSH's terse diagnostics into something actionable."""
    s = (stderr or "").lower()
    if "permission denied" in s:
        raise AuthError(
            "ssh authentication to {} was refused".format(label),
            "Check the username and that your key is in the server's "
            "authorized_keys, or pass an explicit identity file.")
    if "host key verification failed" in s:
        raise AuthError(
            "host key verification failed for {}".format(label),
            "The server's key changed since you last connected.  Confirm this "
            "is expected, then remove the old entry with 'ssh-keygen -R <host>'.")
    if "could not resolve hostname" in s:
        raise TransportError("cannot resolve {}".format(label),
                             "Check the hostname spelling and your DNS.")
    if "connection refused" in s:
        raise TransportError("connection refused by {}".format(label),
                             "Is sshd running, and is the port correct?")
    if "connection timed out" in s or "operation timed out" in s:
        raise TransportError("connection to {} timed out".format(label),
                             "Check the firewall between you and the server.")
    raise TransportError("ssh to {} failed".format(label), (stderr or "").strip())


def _spawn(argv: List[str], display: str, timeout: int,
           sink: Optional[OutputSink], input_text: Optional[str]) -> CommandResult:
    """Run argv, optionally streaming stdout to a sink, and collect everything."""
    start = time.time()
    try:
        if sink is None:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=timeout, input=input_text)
            return CommandResult(display, p.returncode, p.stdout or "",
                                 p.stderr or "", time.time() - start)
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        if input_text:
            proc.stdin.write(input_text)
        if proc.stdin:
            proc.stdin.close()
        out_lines: List[str] = []
        for line in proc.stdout:
            out_lines.append(line)
            sink("out", line.rstrip("\n"))
        proc.wait(timeout=timeout)
        err = proc.stderr.read() if proc.stderr else ""
        if err:
            for line in err.splitlines():
                sink("err", line)
        return CommandResult(display, proc.returncode, "".join(out_lines), err,
                             time.time() - start)
    except subprocess.TimeoutExpired:
        return CommandResult(display, 124, "",
                             "timed out after {}s".format(timeout),
                             time.time() - start)
    except FileNotFoundError as exc:
        raise TransportError("cannot execute {}".format(argv[0]),
                             str(exc)) from exc

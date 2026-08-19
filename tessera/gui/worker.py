"""Background work.

Every operation Tessera performs talks to a server, and some of them take
minutes.  None of it may run on the Qt thread: a frozen window during a package
install is how people conclude a tool has crashed and kill it halfway through,
which is exactly the moment when killing it does the most damage.

So each long operation runs in a QThread and reports back through signals.  The
worker never touches a widget - it emits, and the window decides what to draw.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from ..core.manager import Session
from ..core.models import InstallSpec, Target
from ..core.plan import Step


class _Base(QThread):
    failed = pyqtSignal(str, str)          # message, remedy

    def _fail(self, exc: Exception) -> None:
        message = getattr(exc, "message", None) or str(exc)
        remedy = getattr(exc, "remedy", "")
        if not remedy and not isinstance(exc, Exception.__class__):
            remedy = ""
        self.failed.emit(str(message), str(remedy))


class ConnectWorker(_Base):
    """Open the connection and inspect the target."""

    done = pyqtSignal(object)              # Session

    def __init__(self, target: Target, sudo_password: Optional[str] = None,
                 parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._target = target
        self._password = sudo_password

    def run(self) -> None:
        try:
            session = Session.connect(self._target,
                                      sudo_password=self._password)
            self.done.emit(session)
        except Exception as exc:                               # noqa: BLE001
            self._fail(exc)


class PlanWorker(_Base):
    """Compile a plan without executing it - still needs the network."""

    done = pyqtSignal(object)              # Plan

    def __init__(self, session: Session, spec: InstallSpec,
                 kind: str = "install", engines: Optional[List[str]] = None,
                 options: Optional[Dict] = None,
                 parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._s = session
        self._spec = spec
        self._kind = kind
        self._engines = engines
        self._options = options or {}

    def run(self) -> None:
        try:
            if self._kind == "install":
                plan, _ = self._s.build_install_plan(self._spec)
            else:
                plan = self._s.build_uninstall_plan(self._engines,
                                                    **self._options)
            self.done.emit(plan)
        except Exception as exc:                               # noqa: BLE001
            self._fail(exc)


class ExecuteWorker(_Base):
    """Run an install or an uninstall, streaming progress."""

    #: step index, total, title, state
    progress = pyqtSignal(int, int, str, str)
    output = pyqtSignal(str, str)          # stream, line
    done = pyqtSignal(object, object)      # ExecutionReport, dict of configs

    def __init__(self, session: Session, spec: InstallSpec, kind: str,
                 engines: Optional[List[str]] = None,
                 options: Optional[Dict] = None,
                 parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._s = session
        self._spec = spec
        self._kind = kind
        self._engines = engines
        self._options = options or {}
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        def on_progress(step: Step, index: int, total: int) -> None:
            self.progress.emit(index, total, step.title, step.status.value)

        def on_output(stream: str, line: str) -> None:
            self.output.emit(stream, line)

        try:
            if self._kind == "install":
                report, configs = self._s.install(
                    self._spec, on_progress=on_progress, on_output=on_output)
                self.done.emit(report, configs)
            else:
                report = self._s.uninstall(
                    self._engines, on_progress=on_progress,
                    on_output=on_output, **self._options)
                self.done.emit(report, {})
        except Exception as exc:                               # noqa: BLE001
            self._fail(exc)


class AuditWorker(_Base):
    done = pyqtSignal(object)              # List[Finding]

    def __init__(self, session: Session, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._s = session

    def run(self) -> None:
        try:
            self.done.emit(self._s.audit())
        except Exception as exc:                               # noqa: BLE001
            self._fail(exc)


class StatusWorker(_Base):
    done = pyqtSignal(object)              # dict

    def __init__(self, session: Session, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._s = session

    def run(self) -> None:
        try:
            self.done.emit(self._s.status())
        except Exception as exc:                               # noqa: BLE001
            self._fail(exc)


class PeerWorker(_Base):
    """Add or revoke one peer."""

    added = pyqtSignal(object, str)        # Peer, client config
    removed = pyqtSignal(str)
    def __init__(self, session: Session, action: str, engine: str, name: str,
                 parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._s = session
        self._action = action
        self._engine = engine
        self._name = name

    def run(self) -> None:
        try:
            if self._action == "add":
                peer, conf = self._s.add_peer(self._engine, self._name)
                self.added.emit(peer, conf)
            else:
                self._s.remove_peer(self._engine, self._name)
                self.removed.emit(self._name)
        except Exception as exc:                               # noqa: BLE001
            self._fail(exc)

"""Plans: the reason you can trust this thing.

The reference installers are one long bash function that mutates your server as
it reads.  If it dies at line 400 you own whatever the first 399 lines did, and
the only way to know what those were is to read the script.

Tessera never executes an intention directly.  Every operation - install,
add-peer, harden, uninstall - first *compiles* to a Plan: an ordered list of
Steps, each carrying the exact command that would run, whether it changes
anything, and how to undo it.  Only then is the Plan executed.

Three things fall out of that for free:

  * ``--dry-run`` is not a special code path that can drift from the real one.
    It is the same Plan, printed instead of run.  What you review is literally
    what executes.
  * Failure is not ambiguous.  Every step that ran is recorded, so we can roll
    back in reverse using each step's own undo command.
  * The GUI progress bar is honest, because the total is known before we start.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from .transport import CommandResult, Transport


class StepKind(Enum):
    CHECK = "check"        # reads only; never changes the system
    PACKAGE = "package"    # installs or removes software
    CONFIG = "config"      # writes configuration
    SERVICE = "service"    # starts, stops or enables units
    FIREWALL = "firewall"  # network policy
    KEY = "key"            # generates or destroys key material
    CLEANUP = "cleanup"    # removal, shredding


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class Step:
    """One reviewable unit of change."""

    id: str
    title: str
    kind: StepKind
    #: Shell command to run as root.  Mutually exclusive with ``write``.
    command: str = ""
    #: (path, content, mode) written via the transport's atomic writer.
    write: Optional[tuple] = None
    #: Command that reverses this step, used for rollback and uninstall.
    undo: str = ""
    #: Explanation shown in the UI next to the step.  Written for humans.
    why: str = ""
    #: If set and it returns False at execution time, the step is skipped.
    condition: Optional[Callable[[], bool]] = None
    #: Failure here aborts the plan.  Non-critical steps warn and continue.
    critical: bool = True
    #: Secrets in this step's command must never be logged.
    sensitive: bool = False
    timeout: int = 300

    # -- runtime ---------------------------------------------------------------
    status: StepStatus = StepStatus.PENDING
    result: Optional[CommandResult] = None
    error: str = ""
    duration: float = 0.0

    @property
    def changes_system(self) -> bool:
        return self.kind is not StepKind.CHECK

    def preview(self) -> str:
        """What a dry run prints for this step."""
        if self.write:
            path, content, mode = self.write
            body = "<{} bytes, mode {}>".format(len(content), mode)
            if self.sensitive:
                body = "<{} bytes of key material, mode {}>".format(len(content), mode)
            return "write {} {}".format(path, body)
        return "<secret command hidden>" if self.sensitive else self.command


@dataclass
class Plan:
    """An ordered, reviewable set of Steps."""

    title: str
    steps: List[Step] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def add(self, step: Step) -> Step:
        self.steps.append(step)
        return step

    def extend(self, steps: List[Step]) -> None:
        self.steps.extend(steps)

    def __len__(self) -> int:
        return len(self.steps)

    @property
    def mutating(self) -> List[Step]:
        return [s for s in self.steps if s.changes_system]

    def by_kind(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for s in self.steps:
            counts[s.kind.value] = counts.get(s.kind.value, 0) + 1
        return counts

    def describe(self) -> str:
        lines = ["Plan: {} ({} steps, {} of them change the server)".format(
            self.title, len(self.steps), len(self.mutating))]
        for i, s in enumerate(self.steps, 1):
            lines.append("{:>3}. [{}] {}".format(i, s.kind.value[:5].ljust(5), s.title))
            lines.append("      $ {}".format(s.preview().replace("\n", "\n        ")))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #
@dataclass
class ExecutionReport:
    plan: Plan
    started: float
    finished: float = 0.0
    succeeded: bool = False
    failed_step: Optional[Step] = None
    rolled_back: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.finished or time.time()) - self.started

    @property
    def done_count(self) -> int:
        return sum(1 for s in self.plan.steps if s.status is StepStatus.OK)


#: fn(step, index, total) -> None, called before and after each step.
ProgressHook = Callable[[Step, int, int], None]


class Executor:
    """Runs a Plan against a Transport, with optional rollback."""

    def __init__(self, transport: Transport, *, dry_run: bool = False,
                 rollback_on_failure: bool = True,
                 on_progress: Optional[ProgressHook] = None,
                 on_output: Optional[Callable[[str, str], None]] = None) -> None:
        self.t = transport
        self.dry_run = dry_run
        self.rollback_on_failure = rollback_on_failure
        self.on_progress = on_progress
        self.on_output = on_output
        self._completed: List[Step] = []
        self._cancelled = False

    def cancel(self) -> None:
        """Ask the run to stop after the current step finishes."""
        self._cancelled = True

    def run(self, plan: Plan) -> ExecutionReport:
        report = ExecutionReport(plan=plan, started=time.time())
        total = len(plan.steps)

        for index, step in enumerate(plan.steps, 1):
            if self._cancelled:
                step.status = StepStatus.SKIPPED
                step.error = "cancelled"
                continue

            if step.condition is not None:
                try:
                    if not step.condition():
                        step.status = StepStatus.SKIPPED
                        self._notify(step, index, total)
                        continue
                except Exception as exc:                      # noqa: BLE001
                    step.status = StepStatus.SKIPPED
                    step.error = "condition failed: {}".format(exc)
                    self._notify(step, index, total)
                    continue

            step.status = StepStatus.RUNNING
            self._notify(step, index, total)

            if self.dry_run:
                step.status = StepStatus.OK
                self._notify(step, index, total)
                continue

            started = time.time()
            try:
                self._execute(step)
            except Exception as exc:                          # noqa: BLE001
                step.status = StepStatus.FAILED
                step.error = str(exc)
                step.duration = time.time() - started
                self._notify(step, index, total)
                return self._fail(report, step)

            step.duration = time.time() - started

            if step.status is StepStatus.FAILED:
                self._notify(step, index, total)
                if step.critical:
                    return self._fail(report, step)
                # Non-critical: record and carry on.
                continue

            step.status = StepStatus.OK
            self._completed.append(step)
            self._notify(step, index, total)

        report.succeeded = True
        report.finished = time.time()
        return report

    # -- internals -------------------------------------------------------------
    def _execute(self, step: Step) -> None:
        if step.write is not None:
            path, content, mode = step.write
            self.t.write_file(path, content, mode)
            return
        sink = None
        if self.on_output is not None and not step.sensitive:
            sink = self.on_output
        res = self.t.run_root(step.command, timeout=step.timeout, sink=sink)
        step.result = res
        if not res.ok:
            step.status = StepStatus.FAILED
            step.error = (res.stderr or res.stdout or "").strip()[:2000]

    def _fail(self, report: ExecutionReport, step: Step) -> ExecutionReport:
        report.failed_step = step
        report.succeeded = False
        if self.rollback_on_failure and not self.dry_run:
            report.rolled_back = self._rollback()
        report.finished = time.time()
        return report

    def _rollback(self) -> List[str]:
        """Undo completed steps in reverse.  Best effort: never raises."""
        undone: List[str] = []
        for step in reversed(self._completed):
            if not step.undo:
                continue
            try:
                res = self.t.run_root(step.undo, timeout=60)
                if res.ok:
                    step.status = StepStatus.ROLLED_BACK
                    undone.append(step.id)
            except Exception:                                  # noqa: BLE001
                # A rollback that fails must not mask the original error.
                continue
        return undone

    def _notify(self, step: Step, index: int, total: int) -> None:
        if self.on_progress is not None:
            self.on_progress(step, index, total)

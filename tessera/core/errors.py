"""Exception hierarchy.

Every failure Tessera can produce is one of these, so the CLI and the GUI can
render errors identically instead of each inventing its own handling.  Each
error carries an optional *remedy*: the sentence we would otherwise make the
user search a forum for.
"""

from __future__ import annotations


class TesseraError(Exception):
    """Base class.  Carries a human remedy alongside the message."""

    def __init__(self, message: str, remedy: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.remedy = remedy

    def __str__(self) -> str:
        if self.remedy:
            return "{}\n  -> {}".format(self.message, self.remedy)
        return self.message


class TransportError(TesseraError):
    """Could not reach or talk to the target machine."""


class AuthError(TransportError):
    """Reached the machine but could not authenticate, or could not become root."""


class UnsupportedTargetError(TesseraError):
    """The target OS, kernel or virtualisation cannot host the requested engine."""


class PreflightError(TesseraError):
    """A check that runs before any change was made failed."""


class StepError(TesseraError):
    """A single execution step failed.  Carries the command and its output."""

    def __init__(self, step_id: str, command: str, code: int,
                 stderr: str, remedy: str = "") -> None:
        super().__init__("step '{}' failed (exit {})".format(step_id, code), remedy)
        self.step_id = step_id
        self.command = command
        self.code = code
        self.stderr = stderr


class StateError(TesseraError):
    """The on-server inventory is missing, unreadable or inconsistent."""


class ValidationError(TesseraError):
    """An answer to an interview question is not acceptable."""

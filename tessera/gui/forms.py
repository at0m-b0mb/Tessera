"""The interview, rendered as a form.

The GUI does not have its own list of settings.  It walks
``core.interview.QUESTIONS`` and builds a widget per question, so a question
added for the CLI appears here automatically with the same default, the same
validation and the same explanation.  There is no way for the two to disagree.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QFrame, QLabel,
                             QLineEdit, QSpinBox, QVBoxLayout, QWidget)

from ..core import interview as iv
from ..core.errors import ValidationError
from ..core.models import Facts, InstallSpec
from . import theme
from .widgets import muted


class QuestionField(QFrame):
    """One question: prompt, explanation, input, and inline validation."""

    changed = pyqtSignal()

    def __init__(self, question, spec: InstallSpec, facts: Facts,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.q = question
        self.spec = spec
        self.facts = facts
        self._editor: QWidget

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 14)
        lay.setSpacing(5)

        prompt = QLabel(question.prompt)
        prompt.setStyleSheet(
            "color:%s;font-weight:600;font-size:13px;" % theme.BONE)
        prompt.setWordWrap(True)
        lay.addWidget(prompt)

        if question.why:
            lay.addWidget(muted(question.why))

        default = question.resolve_default(spec, facts)
        self._editor = self._build_editor(default)
        lay.addWidget(self._editor)

        self._error = QLabel("")
        self._error.setWordWrap(True)
        self._error.setStyleSheet("color:%s;font-size:12px;" % theme.DANGER)
        self._error.hide()
        lay.addWidget(self._error)

    # -- editors ---------------------------------------------------------------
    def _build_editor(self, default) -> QWidget:
        q = self.q
        if q.kind == "bool":
            box = QCheckBox("Yes")
            box.setChecked(bool(default))
            box.toggled.connect(self._on_change)
            return box

        if q.kind == "choice":
            combo = QComboBox()
            for value, label in q.choices:
                combo.addItem(label, value)
            index = combo.findData(default)
            combo.setCurrentIndex(max(0, index))
            combo.currentIndexChanged.connect(self._on_change)
            return combo

        if q.kind == "multi":
            holder = QFrame()
            col = QVBoxLayout(holder)
            col.setContentsMargins(0, 0, 0, 0)
            col.setSpacing(4)
            self._boxes: Dict[str, QCheckBox] = {}
            chosen = default or []
            for value, label in q.choices:
                box = QCheckBox(label)
                box.setChecked(value in chosen)
                box.toggled.connect(self._on_change)
                self._boxes[value] = box
                col.addWidget(box)
            return holder

        if q.kind == "int":
            spin = QSpinBox()
            spin.setRange(0, 65535)
            spin.setValue(int(default or 0))
            spin.valueChanged.connect(self._on_change)
            return spin

        edit = QLineEdit()
        if q.kind == "secret":
            edit.setEchoMode(QLineEdit.EchoMode.Password)
        shown = default
        if isinstance(default, list):
            shown = ", ".join(str(x) for x in default)
        edit.setText("" if shown is None else str(shown))
        if q.placeholder:
            edit.setPlaceholderText(q.placeholder)
        edit.textChanged.connect(self._on_change)
        return edit

    # -- value -----------------------------------------------------------------
    def value(self):
        q, w = self.q, self._editor
        if q.kind == "bool":
            return w.isChecked()
        if q.kind == "choice":
            return w.currentData()
        if q.kind == "multi":
            return [v for v, box in self._boxes.items() if box.isChecked()]
        if q.kind == "int":
            return w.value()
        return w.text().strip()

    def _on_change(self, *_) -> None:
        self.changed.emit()

    def apply(self) -> str:
        """Write the answer into the spec.  Returns a warning, if any."""
        warning = iv.answer(self.spec, self.facts, self.q.key, self.value())
        self.set_error("")
        return warning

    def validate(self) -> bool:
        ok, message = self.q.validate(self.value(), self.spec, self.facts)
        self.set_error("" if ok else message)
        return ok

    def set_error(self, message: str) -> None:
        if message:
            self._error.setText(message)
            self._error.show()
            self._editor.setProperty("invalid", "true")
        else:
            self._error.hide()
            self._editor.setProperty("invalid", "false")
        self._editor.style().unpolish(self._editor)
        self._editor.style().polish(self._editor)


class QuestionForm(QWidget):
    """Every applicable question, grouped by section."""

    changed = pyqtSignal()

    def __init__(self, spec: InstallSpec, facts: Facts,
                 advanced: bool = False,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.spec = spec
        self.facts = facts
        self.fields: List[QuestionField] = []
        self._advanced = advanced
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(0)
        self.rebuild()

    def set_advanced(self, on: bool) -> None:
        self._advanced = on
        self.rebuild()

    def rebuild(self) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            widget = item.widget()
            if widget is not None:
                # Detach now: a deferred delete keeps painting the old form
                # underneath the rebuilt one.
                widget.setParent(None)
                widget.deleteLater()
        self.fields = []

        groups: List[str] = []
        for q in iv.QUESTIONS:
            if not q.applies(self.spec, self.facts):
                continue
            if q.advanced and not self._advanced:
                continue
            if q.group and q.group not in groups:
                groups.append(q.group)
                header = QLabel(q.group.upper())
                header.setStyleSheet(
                    "color:%s;font-size:10px;font-weight:700;"
                    "letter-spacing:1.4px;margin-top:14px;margin-bottom:6px;"
                    % theme.BRONZE)
                self._lay.addWidget(header)
            field = QuestionField(q, self.spec, self.facts)
            field.changed.connect(self._on_field_changed)
            self.fields.append(field)
            self._lay.addWidget(field)
        self._lay.addStretch(1)

    def _on_field_changed(self) -> None:
        # Answering "which engines" changes which questions apply, so the form
        # has to be able to grow and shrink while the user is in it.
        engine_field = next((f for f in self.fields if f.q.key == "engines"), None)
        if engine_field is not None:
            current = engine_field.value()
            if current and current != self.spec.engines:
                self.spec.engines = list(current)
                iv.mark_answered(self.spec, "engines")
                self.rebuild()
        self.changed.emit()

    def commit(self) -> List[str]:
        """Apply every answer.  Returns the list of blocking errors."""
        errors: List[str] = []
        for field in self.fields:
            try:
                field.apply()
            except ValidationError as exc:
                field.set_error(exc.message or str(exc))
                errors.append("{}: {}".format(field.q.prompt,
                                              exc.message or str(exc)))
        return errors

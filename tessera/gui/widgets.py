"""Custom widgets.

The mark is drawn rather than shipped as an image file so it stays crisp at any
DPI and can be recoloured per state without a second asset.  It is a square
tile split by an irregular fracture into two halves that only fit each other -
the tessera hospitalis the project is named after, and the same idea as a
keypair.
"""

from __future__ import annotations

from typing import List, Optional

from PyQt6.QtCore import QRectF, QSize, Qt
from PyQt6.QtGui import (QBrush, QColor, QLinearGradient, QPainter,
                         QPainterPath)
from PyQt6.QtWidgets import (QFrame, QHBoxLayout,
                             QLabel, QVBoxLayout, QWidget)

from .. import branding
from . import theme

# The fracture, as fractions of the tile.  Irregular on purpose: a clean
# diagonal reads as a folded card, and the whole point of a tessera is that the
# break is unrepeatable.
_FRACTURE = [(0.50, 0.00), (0.63, 0.15), (0.38, 0.29), (0.66, 0.45),
             (0.35, 0.59), (0.62, 0.73), (0.40, 0.87), (0.50, 1.00)]


class TesseraMark(QWidget):
    """The logo: two halves of a broken tile, slightly separated."""

    def __init__(self, size: int = 48, gap: float = 0.10,
                 left_color: str = theme.BRONZE,
                 right_color: str = theme.BRONZE_DIM,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._size = size
        self._gap = gap
        self._left = QColor(left_color)
        self._right = QColor(right_color)
        self.setFixedSize(size, size)

    def sizeHint(self) -> QSize:
        return QSize(self._size, self._size)

    def set_colors(self, left: str, right: str) -> None:
        self._left, self._right = QColor(left), QColor(right)
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = h = float(min(self.width(), self.height()))
        ox = (self.width() - w) / 2.0
        oy = (self.height() - h) / 2.0
        gap = w * self._gap

        left = QPainterPath()
        left.moveTo(ox, oy)
        for fx, fy in _FRACTURE:
            left.lineTo(ox + fx * w - gap / 2, oy + fy * h)
        left.lineTo(ox, oy + h)
        left.closeSubpath()

        right = QPainterPath()
        right.moveTo(ox + w, oy)
        for fx, fy in _FRACTURE:
            right.lineTo(ox + fx * w + gap / 2, oy + fy * h)
        right.lineTo(ox + w, oy + h)
        right.closeSubpath()

        g1 = QLinearGradient(ox, oy, ox + w * 0.5, oy + h)
        g1.setColorAt(0.0, self._left.lighter(118))
        g1.setColorAt(1.0, self._left)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(g1))
        p.drawPath(left)

        g2 = QLinearGradient(ox + w * 0.5, oy, ox + w, oy + h)
        g2.setColorAt(0.0, self._right)
        g2.setColorAt(1.0, self._right.darker(125))
        p.setBrush(QBrush(g2))
        p.drawPath(right)
        p.end()


class Wordmark(QWidget):
    """Mark plus name plus tagline, for the sidebar and the about box."""

    def __init__(self, version: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        row.addWidget(TesseraMark(34))
        col = QVBoxLayout()
        col.setSpacing(0)
        name = QLabel(branding.NAME)
        name.setStyleSheet(
            "font-size:19px;font-weight:700;letter-spacing:1.5px;color:%s;"
            % theme.BONE)
        sub = QLabel("v{}".format(version) if version else branding.TAGLINE)
        sub.setObjectName("Muted")
        sub.setStyleSheet("font-size:11px;color:%s;" % theme.MUTED)
        col.addWidget(name)
        col.addWidget(sub)
        row.addLayout(col)
        row.addStretch(1)


class Card(QFrame):
    """A padded panel with an optional title."""

    def __init__(self, title: str = "", subtitle: str = "",
                 flat: bool = False, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("CardFlat" if flat else "Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(theme.PAD, theme.PAD, theme.PAD, theme.PAD)
        self.body.setSpacing(10)
        if title:
            head = QLabel(title)
            head.setObjectName("H2")
            self.body.addWidget(head)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("Why")
            sub.setWordWrap(True)
            self.body.addWidget(sub)

    def add(self, widget: QWidget) -> QWidget:
        self.body.addWidget(widget)
        return widget

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)


class StatTile(QFrame):
    """One number with a label - never a number alone."""

    def __init__(self, label: str, value: str = "-", accent: str = theme.BRONZE,
                 hint: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("CardFlat")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(2)
        self._value = QLabel(value)
        self._value.setStyleSheet(
            "font-size:26px;font-weight:700;color:%s;" % accent)
        cap = QLabel(label.upper())
        cap.setStyleSheet(
            "font-size:10px;font-weight:600;letter-spacing:1.2px;color:%s;"
            % theme.MUTED)
        lay.addWidget(self._value)
        lay.addWidget(cap)
        if hint:
            self.setToolTip(hint)

    def set_value(self, value: str, accent: Optional[str] = None) -> None:
        self._value.setText(str(value))
        if accent:
            self._value.setStyleSheet(
                "font-size:26px;font-weight:700;color:%s;" % accent)


class EngineChip(QFrame):
    """Engine name with its accent, used wherever an engine is referenced."""

    def __init__(self, engine: str, active: Optional[bool] = None,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        # The dot carries state, the text carries identity.  Conflating them
        # makes WireGuard - whose own brand colour is red - look broken while
        # it is running perfectly.
        engine_color = theme.ENGINE.get(engine, theme.BRONZE)
        label = branding.ENGINE_LABELS.get(engine, engine)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 5, 12, 5)
        lay.setSpacing(8)
        if active is not None:
            state_color = theme.OK if active else theme.DANGER
            lay.addWidget(_Dot(state_color, 8))
        else:
            lay.addWidget(_Dot(engine_color, 8))
        text = QLabel(label)
        text.setStyleSheet(
            "color:%s;font-weight:600;font-size:12px;" % engine_color)
        lay.addWidget(text)
        if active is not None:
            state = QLabel("running" if active else "stopped")
            state.setStyleSheet(
                "color:%s;font-size:12px;" % (theme.OK if active else theme.DANGER))
            lay.addWidget(state)
        self.setObjectName("EngineChip")
        self.setStyleSheet(
            "QFrame#EngineChip{background:%s;border:1px solid %s;"
            "border-radius:14px;}" % (theme.SLATE, theme.SLATE_HI))


class _Dot(QWidget):
    def __init__(self, color: str, size: int = 8,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._color = QColor(color)
        self._size = size
        self.setFixedSize(size, size)

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self._color)
        p.drawEllipse(0, 0, self._size, self._size)
        p.end()


class StepRow(QFrame):
    """One plan step: state glyph, title, and the reason it exists."""

    def __init__(self, index: int, total: int, title: str, why: str = "",
                 command: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("CardFlat")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(12)

        self._glyph = QLabel("-")
        self._glyph.setFixedWidth(24)
        self._glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._glyph.setStyleSheet(
            "color:%s;font-weight:700;font-size:13px;" % theme.MUTED)
        lay.addWidget(self._glyph)

        col = QVBoxLayout()
        col.setSpacing(1)
        self._title = QLabel("{}/{}  {}".format(index, total, title))
        self._title.setStyleSheet("color:%s;font-size:13px;" % theme.BONE_DIM)
        col.addWidget(self._title)
        if why:
            w = QLabel(why)
            w.setObjectName("Why")
            w.setWordWrap(True)
            col.addWidget(w)
        if command:
            c = QLabel(command if len(command) < 200 else command[:200] + " ...")
            c.setObjectName("Mono")
            c.setWordWrap(True)
            c.setStyleSheet("color:%s;font-size:11px;font-family:%s;"
                            % (theme.MUTED, theme.MONO_STACK))
            col.addWidget(c)
        lay.addLayout(col, 1)

    def set_state(self, state: str) -> None:
        glyphs = {"running": ("...", theme.AMBER), "ok": ("OK", theme.OK),
                  "failed": ("X", theme.DANGER), "skipped": ("-", theme.MUTED),
                  "pending": ("-", theme.MUTED),
                  "rolled_back": ("<", theme.WARN)}
        text, color = glyphs.get(state, ("-", theme.MUTED))
        self._glyph.setText(text)
        self._glyph.setStyleSheet(
            "color:%s;font-weight:700;font-size:13px;" % color)
        self._title.setStyleSheet(
            "color:%s;font-size:13px;%s" % (
                theme.BONE if state in ("ok", "running", "failed") else theme.BONE_DIM,
                "font-weight:600;" if state == "running" else ""))


class FindingRow(QFrame):
    """One audit finding.  Colour and a word, never colour alone."""

    def __init__(self, level: str, title: str, detail: str = "",
                 remedy: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("CardFlat")
        color = theme.level_color(level)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 11, 14, 11)
        lay.setSpacing(12)

        badge = QLabel(theme.level_glyph(level))
        badge.setFixedWidth(30)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(
            "color:%s;font-weight:700;font-size:12px;border:1px solid %s;"
            "border-radius:6px;padding:3px 0;" % (color, color))
        lay.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)

        col = QVBoxLayout()
        col.setSpacing(3)
        head = QLabel(title)
        head.setStyleSheet("color:%s;font-weight:600;font-size:13px;" % theme.BONE)
        head.setWordWrap(True)
        col.addWidget(head)
        if detail:
            d = QLabel(detail)
            d.setObjectName("Why")
            d.setWordWrap(True)
            col.addWidget(d)
        if remedy:
            r = QLabel("-> " + remedy)
            r.setWordWrap(True)
            r.setStyleSheet("color:%s;font-size:12px;" % theme.BRONZE_HI)
            col.addWidget(r)
        lay.addLayout(col, 1)


class QRView(QWidget):
    """Renders a QR code from the module matrix, no image files involved."""

    def __init__(self, data: str = "", size: int = 240,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._matrix: List[List[bool]] = []
        self._size = size
        self.setFixedSize(size, size)
        if data:
            self.set_data(data)

    def set_data(self, data: str) -> None:
        from ..core import qr as qr_mod
        try:
            self._matrix = qr_mod.matrix(data, border=2)
        except Exception:                                      # noqa: BLE001
            self._matrix = []
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor("#FFFFFF"))
        if not self._matrix:
            p.setPen(QColor(theme.MUTED))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "QR unavailable")
            p.end()
            return
        n = len(self._matrix)
        cell = self.width() / float(n)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#0B0D10"))
        for y, row in enumerate(self._matrix):
            x = 0
            while x < n:
                if not row[x]:
                    x += 1
                    continue
                run = x
                while run < n and row[run]:
                    run += 1
                # Merge runs so adjacent modules do not show hairline seams.
                p.drawRect(QRectF(x * cell, y * cell, (run - x) * cell, cell))
                x = run
        p.end()


class VerdictBanner(QFrame):
    """The audit's overall result, stated in words."""

    TEXT = {
        "pass": ("No problems found",
                 "Every check passed."),
        "warn": ("Could be tightened",
                 "Nothing is broken, but some settings are looser than they "
                 "need to be."),
        "fail": ("Needs attention",
                 "One failing check fails the audit. Averaging a fatal flaw "
                 "with nine passes into a good grade would be comforting and "
                 "wrong."),
    }

    def __init__(self, verdict: str = "pass",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        color = theme.level_color(verdict)
        title, detail = self.TEXT.get(verdict, self.TEXT["warn"])
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 15, 18, 15)
        lay.setSpacing(4)
        h = QLabel(title)
        h.setStyleSheet("color:%s;font-size:17px;font-weight:700;" % color)
        d = QLabel(detail)
        d.setObjectName("Why")
        d.setWordWrap(True)
        lay.addWidget(h)
        lay.addWidget(d)
        # Scoped by object name: QLabel inherits from QFrame, so an unscoped
        # "QFrame{...}" rule paints a border around every label inside too.
        self.setObjectName("VerdictBanner")
        self.setStyleSheet(
            "QFrame#VerdictBanner{background:%s;border:1px solid %s;"
            "border-left:4px solid %s;border-radius:%dpx;}"
            % (theme.OBSIDIAN, theme.SLATE_HI, color, theme.RADIUS))


def heading(text: str, level: int = 1) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName({1: "H1", 2: "H2", 3: "H3"}.get(level, "H2"))
    return lab


def muted(text: str, wrap: bool = True) -> QLabel:
    lab = QLabel(text)
    lab.setObjectName("Why")
    lab.setWordWrap(wrap)
    return lab


def hline() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet("background:%s;max-height:1px;border:none;"
                       % theme.SLATE_HI)
    return line

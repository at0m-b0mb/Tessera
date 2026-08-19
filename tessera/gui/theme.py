"""Design tokens and the stylesheet.

Obsidian and bronze, after fired clay and cast metal - deliberately not the
blue that every other VPN product uses, so a screenshot is recognisable at
thumbnail size.

Two rules the stylesheet follows throughout:

  * Colour is never the only signal.  Every state that is shown in colour is
    also shown in a word or a shape, because roughly one man in twelve cannot
    reliably separate the red from the green.
  * Nothing that changes the server is styled as the quiet option.  Destructive
    actions are visually louder than safe ones, not hidden behind a subdued
    "secondary" style that makes them easy to hit by accident.
"""

from __future__ import annotations

from .. import branding

# --- Tokens ------------------------------------------------------------------
INK        = branding.INK          # page background
OBSIDIAN   = branding.OBSIDIAN     # panels
SLATE      = branding.SLATE        # raised surfaces
SLATE_HI   = branding.SLATE_HI     # borders, hover
MUTED      = branding.MUTED
BONE       = branding.BONE
BONE_DIM   = branding.BONE_DIM
BRONZE     = branding.BRONZE
BRONZE_HI  = branding.BRONZE_HI
BRONZE_DIM = branding.BRONZE_DIM
AMBER      = branding.AMBER
OK         = branding.OK
WARN       = branding.WARN
DANGER     = branding.DANGER
INFO       = branding.INFO

ENGINE = branding.ENGINE_COLORS

RADIUS = 10
PAD = 16

FONT_STACK = ('"Inter", "SF Pro Text", "Segoe UI", "Ubuntu", '
              '"Helvetica Neue", sans-serif')
MONO_STACK = ('"JetBrains Mono", "SF Mono", "Cascadia Code", "Consolas", '
              '"DejaVu Sans Mono", monospace')


def stylesheet() -> str:
    return f"""
* {{
    font-family: {FONT_STACK};
    font-size: 13px;
    color: {BONE};
}}
QWidget#Root, QMainWindow, QStackedWidget, QDialog {{ background: {INK}; }}

/* A QScrollArea paints its own viewport from the palette, not from the
   stylesheet of its parent.  Without these three rules the whole content area
   renders on the platform's default light background and every dark-on-dark
   label becomes unreadable. */
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QScrollArea > QWidget > QScrollBar {{ background: transparent; }}

/* ---------- Sidebar ---------- */
QWidget#Sidebar {{
    background: {OBSIDIAN};
    border-right: 1px solid {SLATE_HI};
}}
QPushButton#NavItem {{
    background: transparent;
    border: none;
    border-left: 3px solid transparent;
    padding: 11px 16px;
    text-align: left;
    color: {BONE_DIM};
    font-size: 13px;
}}
QPushButton#NavItem:hover {{
    background: {SLATE};
    color: {BONE};
}}
QPushButton#NavItem:checked {{
    background: {SLATE};
    border-left: 3px solid {BRONZE};
    color: {BRONZE_HI};
    font-weight: 600;
}}
QPushButton#NavItem:disabled {{ color: #3A3F47; }}

/* ---------- Cards ---------- */
QFrame#Card {{
    background: {OBSIDIAN};
    border: 1px solid {SLATE_HI};
    border-radius: {RADIUS}px;
}}
QFrame#CardFlat {{
    background: {SLATE};
    border: 1px solid {SLATE_HI};
    border-radius: {RADIUS}px;
}}

/* ---------- Text ---------- */
QLabel#H1 {{ font-size: 24px; font-weight: 700; color: {BONE}; }}
QLabel#H2 {{ font-size: 17px; font-weight: 600; color: {BONE}; }}
QLabel#H3 {{ font-size: 14px; font-weight: 600; color: {BRONZE_HI}; }}
QLabel#Muted  {{ color: {MUTED}; }}
QLabel#Why    {{ color: {BONE_DIM}; font-size: 12px; }}
QLabel#Mono   {{ font-family: {MONO_STACK}; font-size: 12px; color: {BONE_DIM}; }}
QLabel#Tag    {{
    background: {SLATE}; border: 1px solid {SLATE_HI};
    border-radius: 6px; padding: 2px 8px; color: {BONE_DIM}; font-size: 11px;
}}

/* ---------- Buttons ---------- */
QPushButton {{
    background: {SLATE};
    border: 1px solid {SLATE_HI};
    border-radius: 8px;
    padding: 9px 16px;
    color: {BONE};
}}
QPushButton:hover  {{ background: {SLATE_HI}; border-color: {BRONZE_DIM}; }}
QPushButton:pressed{{ background: {OBSIDIAN}; }}
QPushButton:disabled {{ color: #4A4F57; border-color: {SLATE}; background: {OBSIDIAN}; }}

/* Selection has to be visible.  Without this a chosen profile looks the same
   as the three that were not chosen. */
QPushButton:checked {{
    background: {SLATE_HI};
    border: 1px solid {BRONZE};
    color: {BRONZE_HI};
    font-weight: 600;
}}

QPushButton#Primary {{
    background: {BRONZE};
    border: 1px solid {BRONZE};
    color: #17120C;
    font-weight: 600;
}}
QPushButton#Primary:hover   {{ background: {BRONZE_HI}; border-color: {BRONZE_HI}; }}
QPushButton#Primary:pressed {{ background: {BRONZE_DIM}; }}
QPushButton#Primary:disabled{{ background: {SLATE}; color: #4A4F57; border-color: {SLATE_HI}; }}

/* Destructive actions are louder than safe ones, never quieter. */
QPushButton#Danger {{
    background: transparent;
    border: 1px solid {DANGER};
    color: {DANGER};
    font-weight: 600;
}}
QPushButton#Danger:hover {{ background: {DANGER}; color: #1A0C0D; }}

QPushButton#Ghost {{
    background: transparent; border: none; color: {BRONZE_HI};
    padding: 6px 8px; text-decoration: underline;
}}
QPushButton#Ghost:hover {{ color: {AMBER}; }}

/* ---------- Inputs ---------- */
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {INK};
    border: 1px solid {SLATE_HI};
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: {BRONZE_DIM};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {{
    border-color: {BRONZE};
}}
QLineEdit[invalid="true"] {{ border-color: {DANGER}; }}
QLineEdit::placeholder {{ color: {MUTED}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {OBSIDIAN}; border: 1px solid {SLATE_HI};
    selection-background-color: {SLATE_HI}; outline: none;
}}
QPlainTextEdit#Console {{
    font-family: {MONO_STACK}; font-size: 12px;
    background: #08090B; border: 1px solid {SLATE_HI}; color: {BONE_DIM};
}}

/* ---------- Checkbox / radio ---------- */
QCheckBox, QRadioButton {{ spacing: 9px; padding: 3px 0; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 17px; height: 17px;
    border: 1px solid {SLATE_HI}; background: {INK};
}}
QCheckBox::indicator {{ border-radius: 5px; }}
QRadioButton::indicator {{ border-radius: 9px; }}
QCheckBox::indicator:hover, QRadioButton::indicator:hover {{ border-color: {BRONZE}; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background: {BRONZE}; border-color: {BRONZE};
}}

/* ---------- Tables ---------- */
QTableWidget, QTableView {{
    background: {OBSIDIAN};
    border: 1px solid {SLATE_HI};
    border-radius: {RADIUS}px;
    gridline-color: {SLATE};
    selection-background-color: {SLATE_HI};
    outline: none;
}}
QHeaderView::section {{
    background: {SLATE};
    color: {BRONZE_HI};
    border: none;
    border-bottom: 1px solid {SLATE_HI};
    padding: 9px 10px;
    font-weight: 600;
    font-size: 12px;
}}
QTableWidget::item {{ padding: 8px 10px; border-bottom: 1px solid {SLATE}; }}

/* ---------- Scrollbars ---------- */
QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {SLATE_HI}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {BRONZE_DIM}; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle:horizontal {{
    background: {SLATE_HI}; border-radius: 5px; min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* ---------- Misc ---------- */
QProgressBar {{
    background: {SLATE}; border: none; border-radius: 4px;
    height: 7px; text-align: center; color: transparent;
}}
QProgressBar::chunk {{ background: {BRONZE}; border-radius: 4px; }}
QScrollArea {{ border: none; background: transparent; }}
QToolTip {{
    background: {SLATE}; color: {BONE};
    border: 1px solid {BRONZE_DIM}; padding: 6px 9px; border-radius: 6px;
}}
QSplitter::handle {{ background: {SLATE_HI}; }}
"""


def level_color(level: str) -> str:
    return {"pass": OK, "ok": OK, "warn": WARN, "fail": DANGER,
            "info": INFO}.get(level, MUTED)


def level_glyph(level: str) -> str:
    """A shape as well as a colour, for anyone who cannot separate the hues."""
    return {"pass": "OK", "ok": "OK", "warn": "!", "fail": "X",
            "info": "i"}.get(level, "-")


def apply_palette(app) -> None:
    """Set the application palette to match the stylesheet.

    Some widgets - scroll-area viewports, native dialogs, tooltips - draw from
    the palette rather than the stylesheet.  Setting both is what stops a
    single light-grey rectangle appearing in the middle of a dark window.
    """
    from PyQt6.QtGui import QColor, QPalette

    p = QPalette()
    p.setColor(QPalette.ColorRole.Window, QColor(INK))
    p.setColor(QPalette.ColorRole.WindowText, QColor(BONE))
    p.setColor(QPalette.ColorRole.Base, QColor(INK))
    p.setColor(QPalette.ColorRole.AlternateBase, QColor(OBSIDIAN))
    p.setColor(QPalette.ColorRole.Text, QColor(BONE))
    p.setColor(QPalette.ColorRole.Button, QColor(SLATE))
    p.setColor(QPalette.ColorRole.ButtonText, QColor(BONE))
    p.setColor(QPalette.ColorRole.Highlight, QColor(BRONZE))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor("#17120C"))
    p.setColor(QPalette.ColorRole.ToolTipBase, QColor(SLATE))
    p.setColor(QPalette.ColorRole.ToolTipText, QColor(BONE))
    p.setColor(QPalette.ColorRole.PlaceholderText, QColor(MUTED))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,
               QColor("#4A4F57"))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText,
               QColor("#4A4F57"))
    app.setPalette(p)

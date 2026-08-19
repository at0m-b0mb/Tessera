"""The desktop application.

One window, a sidebar, and six pages.  The sidebar disables everything except
Connect until a session exists, because a VPN manager showing an empty peer
table when it simply is not connected is a tool that lies to you.

Nothing here reaches for a shell.  Every page drives a ``Session`` through a
worker thread, which is the same object the CLI uses.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import (QColor, QGuiApplication)
from PyQt6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QComboBox,
                             QDialog, QFileDialog, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog,
                             QLabel, QLineEdit, QMainWindow, QMessageBox,
                             QPlainTextEdit, QProgressBar, QPushButton,
                             QScrollArea, QSizePolicy, QSpinBox, QStackedWidget,
                             QTableWidget, QTableWidgetItem, QVBoxLayout,
                             QWidget)

from .. import __version__, branding
from ..core import interview as iv
from ..core import qr as qr_mod
from ..core.audit import tally, verdict
from ..core.manager import Session, quick_target
from ..core.models import InstallSpec, Peer
from ..core.plan import Plan
from ..core.state import summary_line
from . import theme
from .forms import QuestionForm
from .widgets import (Card, EngineChip, FindingRow, QRView, StatTile, StepRow,
                      VerdictBanner, Wordmark, heading, hline,
                      muted)
from .worker import (AuditWorker, ConnectWorker, ExecuteWorker, PeerWorker,
                     PlanWorker, StatusWorker)

PAGES = ["Connect", "Install", "Dashboard", "Devices", "Audit", "Remove"]


def clear_layout(layout) -> None:
    """Empty a layout immediately, including nested layouts.

    ``deleteLater()`` schedules deletion for the next event-loop turn, so a
    widget removed from a layout but not yet deleted keeps painting at its last
    geometry - which shows up as stale text floating over the new content.
    Reparenting to None detaches it now; deleteLater then frees it.
    """
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
            continue
        child = item.layout()
        if child is not None:
            clear_layout(child)
            child.deleteLater()


def scroller(inner: QWidget) -> QScrollArea:
    """Vertical-only scrolling that actually wraps its contents.

    A QScrollArea sizes itself to the widest child's sizeHint.  A word-wrapped
    QLabel reports the width of its text on one line, so without constraining
    the inner widget the whole page grows wider than the viewport and the
    explanations get clipped off the right edge - which is exactly the text a
    first-time user most needs to read.
    """
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setWidget(inner)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    inner.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Minimum)
    return area


class Page(QWidget):
    """Base page: a titled, scrolling column."""

    def __init__(self, title: str, subtitle: str = "",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        inner = QWidget()
        self.col = QVBoxLayout(inner)
        self.col.setContentsMargins(28, 24, 28, 28)
        self.col.setSpacing(14)
        self.col.addWidget(heading(title, 1))
        if subtitle:
            self.col.addWidget(muted(subtitle))
        outer.addWidget(scroller(inner))

    def add(self, widget: QWidget) -> QWidget:
        self.col.addWidget(widget)
        return widget

    def stretch(self) -> None:
        self.col.addStretch(1)


# --------------------------------------------------------------------------- #
# Connect
# --------------------------------------------------------------------------- #
class ConnectPage(Page):
    connected = pyqtSignal(object)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(
            "Connect to a server",
            "Tessera runs here and configures a Linux server over SSH. "
            "It never needs to be installed on the server itself.", parent)
        self._worker: Optional[ConnectWorker] = None

        card = Card("Target")
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.setVerticalSpacing(9)

        self.host = QLineEdit()
        self.host.setPlaceholderText("user@vpn.example.com   (or: local, demo)")
        self.host.returnPressed.connect(self.connect_now)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(22)
        self.identity = QLineEdit()
        self.identity.setPlaceholderText("optional - defaults to your ssh-agent "
                                         "and ~/.ssh/config")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._pick_key)

        grid.addWidget(QLabel("Server"), 0, 0)
        grid.addWidget(self.host, 0, 1, 1, 2)
        grid.addWidget(QLabel("SSH port"), 1, 0)
        grid.addWidget(self.port, 1, 1)
        grid.addWidget(QLabel("Key file"), 2, 0)
        grid.addWidget(self.identity, 2, 1)
        grid.addWidget(browse, 2, 2)
        card.add_layout(grid)

        card.add(muted(
            "Connections use your system's own ssh client, so ~/.ssh/config "
            "aliases, ProxyJump bastions, hardware keys and known_hosts all "
            "work exactly as they do in your terminal. Tessera never "
            "implements its own host-key trust."))

        row = QHBoxLayout()
        self.go = QPushButton("Connect")
        self.go.setObjectName("Primary")
        self.go.clicked.connect(self.connect_now)
        demo = QPushButton("Try the demo server")
        demo.clicked.connect(self._demo)
        row.addWidget(self.go)
        row.addWidget(demo)
        row.addStretch(1)
        card.add_layout(row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setObjectName("Why")
        card.add(self.status)
        self.add(card)

        info = Card("What Tessera will do",
                    "Nothing is changed until you review a plan and approve it.")
        for title, body in [
            ("Inspect first",
             "Detects the distribution, kernel, virtualisation, firewall and "
             "what is already installed - all read-only."),
            ("Compile a plan",
             "Every change becomes a numbered step with the exact command. "
             "You see it before anything runs."),
            ("Keep an inventory",
             "Everything created is written to /etc/tessera/state.json, which "
             "is how the uninstaller later removes exactly that and nothing "
             "else."),
        ]:
            block = QVBoxLayout()
            block.setSpacing(1)
            h = QLabel(title)
            h.setObjectName("H3")
            block.addWidget(h)
            block.addWidget(muted(body))
            info.add_layout(block)
        self.add(info)
        self.stretch()

    def _pick_key(self) -> None:
        start = os.path.expanduser("~/.ssh")
        path, _ = QFileDialog.getOpenFileName(self, "Select an SSH private key",
                                              start)
        if path:
            self.identity.setText(path)

    def _demo(self) -> None:
        self.host.setText("demo")
        self.connect_now()

    def connect_now(self) -> None:
        raw = self.host.text().strip()
        target = quick_target(raw)
        if not target.is_local and target.host != "demo":
            if self.port.value() != 22:
                target.port = self.port.value()
            target.identity = self.identity.text().strip()

        self.go.setEnabled(False)
        self.status.setText("Connecting to {} ...".format(target.display()))
        self._worker = ConnectWorker(target)
        self._worker.done.connect(self._ok)
        self._worker.failed.connect(self._err)
        self._worker.start()

    def _ok(self, session: Session) -> None:
        self.go.setEnabled(True)
        self.status.setText("Connected: {}".format(session.facts.summary()))
        self.status.setStyleSheet("color:%s;" % theme.OK)
        self.connected.emit(session)

    def _err(self, message: str, remedy: str) -> None:
        self.go.setEnabled(True)
        self.status.setText(message + ("\n" + remedy if remedy else ""))
        self.status.setStyleSheet("color:%s;" % theme.DANGER)


# --------------------------------------------------------------------------- #
# Install
# --------------------------------------------------------------------------- #
class InstallPage(Page):
    installed = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__("Install",
                         "Answer as much or as little as you like. "
                         "Every question has a safe default.", parent)
        self.session: Optional[Session] = None
        self.spec = InstallSpec()
        self.form: Optional[QuestionForm] = None
        self._worker = None
        self._rows: List[StepRow] = []

        self.profile_card = Card("How much do you want to be asked?")
        grid = QGridLayout()
        grid.setSpacing(8)
        self._profile_buttons = QButtonGroup(self)
        self._profile_buttons.setExclusive(True)
        for i, (key, meta) in enumerate(iv.PROFILES.items()):
            btn = QPushButton(meta["label"])
            btn.setCheckable(True)
            btn.setChecked(key == "balanced")
            btn.setMinimumHeight(40)
            btn.setToolTip(meta["detail"])
            btn.setProperty("profile", key)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding,
                              QSizePolicy.Policy.Fixed)
            btn.clicked.connect(self._profile_changed)
            self._profile_buttons.addButton(btn)
            grid.addWidget(btn, i // 2, i % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        self.profile_card.add_layout(grid)
        self.profile_hint = muted(iv.PROFILES["balanced"]["detail"])
        self.profile_card.add(self.profile_hint)
        self.add(self.profile_card)

        self.form_card = Card("Settings")
        self.advanced = QCheckBox("Show advanced settings")
        self.advanced.toggled.connect(self._toggle_advanced)
        self.form_card.add(self.advanced)
        self.form_holder = QWidget()
        self.form_layout = QVBoxLayout(self.form_holder)
        self.form_layout.setContentsMargins(0, 0, 0, 0)
        self.form_card.add(self.form_holder)
        self.add(self.form_card)

        actions = QHBoxLayout()
        self.preview_btn = QPushButton("Preview the plan")
        self.preview_btn.clicked.connect(self._preview)
        self.apply_btn = QPushButton("Install")
        self.apply_btn.setObjectName("Primary")
        self.apply_btn.clicked.connect(self._apply)
        actions.addWidget(self.preview_btn)
        actions.addWidget(self.apply_btn)
        actions.addStretch(1)
        self.col.addLayout(actions)

        self.plan_card = Card("Plan",
                              "Exactly what will run, in order. Nothing has "
                              "happened yet.")
        self.plan_body = QVBoxLayout()
        self.plan_body.setSpacing(6)
        self.plan_card.add_layout(self.plan_body)
        self.plan_card.hide()
        self.add(self.plan_card)

        self.progress = QProgressBar()
        self.progress.hide()
        self.add(self.progress)

        self.console = QPlainTextEdit()
        self.console.setObjectName("Console")
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(140)
        self.console.hide()
        self.add(self.console)
        self.stretch()

    # -- wiring ---------------------------------------------------------------
    def set_session(self, session: Session) -> None:
        self.session = session
        self.spec = InstallSpec(target=session.target)
        iv.apply_profile(self.spec, self._profile(), session.facts)
        self._rebuild_form()

    def _profile(self) -> str:
        btn = self._profile_buttons.checkedButton()
        return btn.property("profile") if btn else "balanced"

    def _profile_changed(self) -> None:
        self.profile_hint.setText(iv.PROFILES[self._profile()]["detail"])
        if not self.session:
            return
        engines = list(self.spec.engines)
        self.spec = InstallSpec(target=self.session.target)
        self.spec.engines = engines
        iv.apply_profile(self.spec, self._profile(), self.session.facts)
        self.advanced.setChecked(self._profile() == "custom")
        self._rebuild_form()

    def _toggle_advanced(self, on: bool) -> None:
        if self.form:
            self.form.set_advanced(on)

    def _rebuild_form(self) -> None:
        clear_layout(self.form_layout)
        if not self.session:
            return
        self.form = QuestionForm(self.spec, self.session.facts,
                                 advanced=self.advanced.isChecked())
        self.form_layout.addWidget(self.form)

    def _collect(self) -> bool:
        if not self.form:
            return False
        errors = self.form.commit()
        if errors:
            QMessageBox.warning(self, "Check these answers",
                                "\n\n".join(errors[:6]))
            return False
        if not self.spec.engines:
            QMessageBox.warning(self, "Nothing selected",
                                "Choose at least one VPN to install.")
            return False
        return True

    def _preview(self) -> None:
        if not self.session or not self._collect():
            return
        issues = self.session.preflight(self.spec)
        blocking = [i for i in issues if i[0] == "block"]
        if blocking:
            QMessageBox.critical(
                self, "Cannot install",
                "\n\n".join(m for _, _, m in blocking) +
                "\n\nNothing has been changed.")
            return
        if issues:
            warn = "\n\n".join(m for _, _, m in issues)
            if QMessageBox.question(
                    self, "Before you continue", warn + "\n\nContinue anyway?",
                    QMessageBox.StandardButton.Yes |
                    QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
        self._worker = PlanWorker(self.session, self.spec, "install")
        self._worker.done.connect(self._show_plan)
        self._worker.failed.connect(self._fail)
        self._worker.start()

    def _show_plan(self, plan: Plan) -> None:
        clear_layout(self.plan_body)
        self._rows = []
        total = len(plan.steps)
        for i, step in enumerate(plan.steps, 1):
            row = StepRow(i, total, step.title, step.why, step.preview())
            self._rows.append(row)
            self.plan_body.addWidget(row)
        for note in plan.notes:
            self.plan_body.addWidget(muted(note))
        self.plan_card.show()

    def _apply(self) -> None:
        if not self.session or not self._collect():
            return
        plan_len = "these changes"
        if QMessageBox.question(
                self, "Install",
                "Apply {} to {}?\n\nEvery change is recorded so it can be "
                "removed cleanly later.".format(
                    plan_len, self.spec.target.display()),
                QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return

        self.apply_btn.setEnabled(False)
        self.preview_btn.setEnabled(False)
        self.progress.show()
        self.progress.setValue(0)
        self.console.show()
        self.console.clear()

        self._worker = ExecuteWorker(self.session, self.spec, "install")
        self._worker.progress.connect(self._on_step)
        self._worker.output.connect(self._on_output)
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._fail)
        self._worker.start()

    def _on_step(self, index: int, total: int, title: str, state: str) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(index if state != "running" else index - 1)
        if not self.plan_card.isVisible() or index > len(self._rows):
            self.console.appendPlainText("[{}/{}] {}".format(index, total, title))
            return
        self._rows[index - 1].set_state(state)

    def _on_output(self, stream: str, line: str) -> None:
        self.console.appendPlainText(line)

    def _on_done(self, report, configs: Dict[str, str]) -> None:
        self.apply_btn.setEnabled(True)
        self.preview_btn.setEnabled(True)
        if not report.succeeded:
            step = report.failed_step
            QMessageBox.critical(
                self, "Install failed",
                "Stopped at: {}\n\n{}\n\n{}".format(
                    step.title if step else "unknown",
                    (step.error if step else "")[:600],
                    "Rolled back {} completed step(s).".format(
                        len(report.rolled_back)) if report.rolled_back
                    else "No changes were rolled back."))
            return
        self.progress.setValue(self.progress.maximum())
        if configs:
            ClientConfigDialog(configs, self).exec()
        else:
            QMessageBox.information(self, "Installed",
                                    "Done in {:.0f} seconds.".format(
                                        report.duration))
        self.installed.emit()

    def _fail(self, message: str, remedy: str) -> None:
        self.apply_btn.setEnabled(True)
        self.preview_btn.setEnabled(True)
        QMessageBox.critical(self, "Error",
                             message + ("\n\n" + remedy if remedy else ""))


# --------------------------------------------------------------------------- #
# Client config dialog
# --------------------------------------------------------------------------- #
class ClientConfigDialog(QDialog):
    """Shows a generated config, its QR code, and how to save it."""

    def __init__(self, configs: Dict[str, str],
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Client configuration")
        self.setMinimumSize(760, 560)
        self._configs = configs

        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.addWidget(heading("Your device is ready", 2))
        lay.addWidget(muted(
            "The private key in this file was generated on this computer and "
            "was never sent to the server. Save it somewhere safe - Tessera "
            "cannot produce it again, by design."))

        self.picker = QComboBox()
        for key in configs:
            engine, _, peer = key.partition(":")
            self.picker.addItem("{} - {}".format(
                branding.ENGINE_LABELS.get(engine, engine), peer), key)
        self.picker.currentIndexChanged.connect(self._refresh)
        if len(configs) > 1:
            lay.addWidget(self.picker)

        split = QHBoxLayout()
        self.text = QPlainTextEdit()
        self.text.setObjectName("Console")
        self.text.setReadOnly(True)
        split.addWidget(self.text, 3)

        side = QVBoxLayout()
        self.qr = QRView(size=250)
        side.addWidget(self.qr)
        self.qr_note = muted("Scan with the WireGuard app.")
        side.addWidget(self.qr_note)
        side.addStretch(1)
        split.addLayout(side, 2)
        lay.addLayout(split)

        row = QHBoxLayout()
        save = QPushButton("Save to file")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        copy = QPushButton("Copy to clipboard")
        copy.clicked.connect(self._copy)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(save)
        row.addWidget(copy)
        row.addStretch(1)
        row.addWidget(close)
        lay.addLayout(row)
        self._refresh()

    def _current(self) -> str:
        key = self.picker.currentData() or next(iter(self._configs))
        return self._configs[key]

    def _refresh(self) -> None:
        content = self._current()
        self.text.setPlainText(content)
        key = self.picker.currentData() or ""
        if key.startswith("wireguard") and qr_mod.available():
            self.qr.show()
            self.qr_note.show()
            self.qr.set_data(content)
        else:
            self.qr.hide()
            self.qr_note.setText(
                "OpenVPN profiles are too large for a QR code - save the "
                ".ovpn file and open it in your client.")

    def _save(self) -> None:
        key = self.picker.currentData() or next(iter(self._configs))
        engine, _, peer = key.partition(":")
        ext = ".conf" if engine == "wireguard" else ".ovpn"
        path, _sel = QFileDialog.getSaveFileName(
            self, "Save client configuration",
            os.path.join(os.path.expanduser("~"),
                         "{}-{}{}".format(engine, peer, ext)))
        if not path:
            return
        # Created 0600 from the outset: writing then chmod-ing leaves a window
        # in which the key is world-readable.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(self._current())
        QMessageBox.information(self, "Saved",
                                "Written to {}\nPermissions: owner only."
                                .format(path))

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(self._current())
        QMessageBox.information(
            self, "Copied",
            "The configuration is on your clipboard. It contains a private "
            "key - paste it where you need it, then copy something else.")


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
class DashboardPage(Page):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__("Dashboard", parent=parent)
        self.session: Optional[Session] = None
        self._worker = None

        self.summary = Card("Server")
        self.summary_body = QVBoxLayout()
        self.summary.add_layout(self.summary_body)
        self.add(self.summary)

        self.tiles = QHBoxLayout()
        self.tile_engines = StatTile("VPNs installed", "-")
        self.tile_peers = StatTile("Devices", "-")
        self.tile_online = StatTile("Online now", "-", theme.OK)
        self.tile_traffic = StatTile("Transferred", "-", theme.INFO)
        for t in (self.tile_engines, self.tile_peers, self.tile_online,
                  self.tile_traffic):
            self.tiles.addWidget(t)
        self.col.addLayout(self.tiles)

        self.engines_card = Card("Services")
        self.engines_body = QVBoxLayout()
        self.engines_card.add_layout(self.engines_body)
        self.add(self.engines_card)

        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        row = QHBoxLayout()
        row.addWidget(refresh)
        row.addStretch(1)
        self.col.addLayout(row)
        self.stretch()

    def set_session(self, session: Session) -> None:
        self.session = session
        self._render_summary()
        self.refresh()

    def _render_summary(self) -> None:
        clear_layout(self.summary_body)
        if not self.session:
            return
        f = self.session.facts
        grid = QGridLayout()
        rows = [("Target", self.session.target.display()),
                ("Operating system", "{} {}".format(f.os_name or f.os_id,
                                                    f.version_id)),
                ("Kernel", f.kernel), ("Architecture", f.arch),
                ("Virtualisation", f.virt or "none"),
                ("Public address", f.public_ipv4 or "not detected"),
                ("Firewall", f.firewall),
                ("Managed", summary_line(self.session.state))]
        for i, (k, v) in enumerate(rows):
            key = QLabel(k)
            key.setObjectName("Muted")
            key.setStyleSheet("color:%s;" % theme.MUTED)
            grid.addWidget(key, i // 2, (i % 2) * 2)
            grid.addWidget(QLabel(str(v)), i // 2, (i % 2) * 2 + 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        self.summary_body.addLayout(grid)

    def refresh(self) -> None:
        if not self.session:
            return
        self._worker = StatusWorker(self.session)
        self._worker.done.connect(self._render)
        self._worker.failed.connect(lambda m, r: None)
        self._worker.start()

    def _render(self, status: Dict) -> None:
        clear_layout(self.engines_body)

        online = 0
        traffic = 0
        # Configured devices come from the inventory; "online" comes from the
        # live service.  Counting both from the live dump would under-report
        # every device that has simply not connected yet.
        peers = len([x for x in self.session.list_peers() if not x.revoked]) \
            if self.session else 0
        for name, info in status.items():
            chip_row = QHBoxLayout()
            chip_row.addWidget(EngineChip(name, bool(info.get("active"))))
            chip_row.addStretch(1)
            self.engines_body.addLayout(chip_row)
            for p in info.get("peers", []):
                traffic += int(p.get("rx_bytes", 0)) + int(p.get("tx_bytes", 0))
                if p.get("online") or p.get("last_handshake", 0):
                    online += 1
        if not status:
            self.engines_body.addWidget(muted(
                "Nothing installed yet. Use the Install page."))

        from ..cli.ui import human_bytes
        self.tile_engines.set_value(str(len(status)))
        self.tile_peers.set_value(str(peers))
        self.tile_online.set_value(str(online))
        self.tile_traffic.set_value(human_bytes(traffic))


# --------------------------------------------------------------------------- #
# Devices
# --------------------------------------------------------------------------- #
class PeersPage(Page):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__("Devices",
                         "Each device gets its own keys, so revoking one "
                         "never affects the others.", parent)
        self.session: Optional[Session] = None
        self._worker = None

        row = QHBoxLayout()
        self.engine_pick = QComboBox()
        self.name = QLineEdit()
        self.name.setPlaceholderText("device name, e.g. work-laptop")
        self.name.returnPressed.connect(self._add)
        add = QPushButton("Add device")
        add.setObjectName("Primary")
        add.clicked.connect(self._add)
        row.addWidget(self.engine_pick)
        row.addWidget(self.name, 1)
        row.addWidget(add)
        self.col.addLayout(row)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Device", "VPN", "Address / identity", "Added", "State", ""])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(5, 112)
        self.table.verticalHeader().hide()
        # Rows must be tall enough for an embedded button, or the label inside
        # it gets clipped to an empty outline.
        self.table.verticalHeader().setDefaultSectionSize(44)
        self.table.setMinimumHeight(320)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.add(self.table)
        self.stretch()

    def set_session(self, session: Session) -> None:
        self.session = session
        self.engine_pick.clear()
        for name in session.state.installed_engines:
            if name != "tailscale":
                self.engine_pick.addItem(
                    branding.ENGINE_LABELS.get(name, name), name)
        self.reload()

    def reload(self) -> None:
        if not self.session:
            return
        peers = self.session.list_peers()
        self.table.setRowCount(0)
        for peer in peers:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(peer.name))

            # Which VPN a device belongs to is not optional information: the
            # same name can legitimately exist on two engines at once.
            engine_item = QTableWidgetItem(
                branding.ENGINE_LABELS.get(peer.engine, peer.engine))
            engine_item.setForeground(
                QColor(theme.ENGINE.get(peer.engine, theme.BRONZE)))
            self.table.setItem(r, 1, engine_item)

            if peer.address_v4:
                identity = peer.address_v4
            elif peer.fingerprint:
                identity = "cert " + peer.fingerprint[:17] + "..."
            else:
                identity = "-"
            self.table.setItem(r, 2, QTableWidgetItem(identity))
            self.table.setItem(r, 3, QTableWidgetItem(peer.created[:10]))

            state = QTableWidgetItem("revoked" if peer.revoked else "active")
            state.setForeground(QColor(theme.MUTED if peer.revoked else theme.OK))
            self.table.setItem(r, 4, state)

            # Set the row height explicitly.  A cell widget is given the cell
            # rectangle, and the default row is shorter than a button, so the
            # label inside gets clipped to an empty red outline.
            self.table.setRowHeight(r, 44)
            if not peer.revoked:
                btn = QPushButton("Revoke")
                btn.setObjectName("Danger")
                btn.setFixedHeight(28)
                btn.setMinimumWidth(90)
                btn.setStyleSheet("padding: 2px 12px; font-size: 12px;")
                btn.clicked.connect(lambda _, x=peer: self._remove(x))
                self.table.setCellWidget(r, 5, btn)

    def _add(self) -> None:
        if not self.session:
            return
        name = self.name.text().strip()
        engine = self.engine_pick.currentData()
        if not name or not engine:
            QMessageBox.warning(self, "Name required",
                                "Give the device a name first.")
            return
        self._worker = PeerWorker(self.session, "add", engine, name)
        self._worker.added.connect(self._added)
        self._worker.failed.connect(
            lambda m, r: QMessageBox.critical(
                self, "Could not add device", m + ("\n\n" + r if r else "")))
        self._worker.start()

    def _added(self, peer: Peer, config: str) -> None:
        self.name.clear()
        self.reload()
        ClientConfigDialog({"{}:{}".format(peer.engine, peer.name): config},
                           self).exec()

    def _remove(self, peer: Peer) -> None:
        if QMessageBox.question(
                self, "Revoke device",
                "Revoke '{}'?\n\nThe device stops working immediately and "
                "cannot be restored - you would have to issue new keys."
                .format(peer.name),
                QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self._worker = PeerWorker(self.session, "remove", peer.engine, peer.name)
        self._worker.removed.connect(lambda _: self.reload())
        self._worker.failed.connect(
            lambda m, r: QMessageBox.critical(self, "Could not revoke", m))
        self._worker.start()


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
class AuditPage(Page):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__("Security audit",
                         "Read-only. Nothing on this page changes the server.",
                         parent)
        self.session: Optional[Session] = None
        self._worker = None

        row = QHBoxLayout()
        self.run_btn = QPushButton("Run audit")
        self.run_btn.setObjectName("Primary")
        self.run_btn.clicked.connect(self.run_audit)
        row.addWidget(self.run_btn)
        row.addStretch(1)
        self.col.addLayout(row)

        self.banner_holder = QVBoxLayout()
        self.col.addLayout(self.banner_holder)

        self.tiles = QHBoxLayout()
        self.t_pass = StatTile("Passed", "-", theme.OK)
        self.t_warn = StatTile("Warnings", "-", theme.WARN)
        self.t_fail = StatTile("Failures", "-", theme.DANGER)
        for t in (self.t_pass, self.t_warn, self.t_fail):
            self.tiles.addWidget(t)
        self.tiles.addStretch(1)
        self.col.addLayout(self.tiles)

        self.findings = QVBoxLayout()
        self.findings.setSpacing(7)
        self.col.addLayout(self.findings)
        self.stretch()

    def set_session(self, session: Session) -> None:
        self.session = session

    def run_audit(self) -> None:
        if not self.session:
            return
        self.run_btn.setEnabled(False)
        self._worker = AuditWorker(self.session)
        self._worker.done.connect(self._render)
        self._worker.failed.connect(
            lambda m, r: (self.run_btn.setEnabled(True),
                          QMessageBox.critical(self, "Audit failed", m)))
        self._worker.start()

    def _render(self, findings: List) -> None:
        self.run_btn.setEnabled(True)
        clear_layout(self.banner_holder)
        clear_layout(self.findings)

        self.banner_holder.addWidget(VerdictBanner(verdict(findings)))
        counts = tally(findings)
        self.t_pass.set_value(str(counts["pass"]))
        self.t_warn.set_value(str(counts["warn"]))
        self.t_fail.set_value(str(counts["fail"]))

        order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
        for f in sorted(findings, key=lambda x: order.get(x.level, 9)):
            self.findings.addWidget(
                FindingRow(f.level, f.title, f.detail, f.remedy))


# --------------------------------------------------------------------------- #
# Remove
# --------------------------------------------------------------------------- #
class RemovePage(Page):
    removed = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(
            "Remove",
            "Tessera removes exactly what it installed, and shreds key "
            "material on the way out.", parent)
        self.session: Optional[Session] = None
        self._worker = None
        self._rows: List[StepRow] = []

        explain = Card("How removal works")
        for title, body in [
            ("It follows the inventory",
             "Every file, package, service, firewall rule and kernel setting "
             "Tessera created was written down at the time. Removal walks that "
             "list backwards."),
            ("It leaves your server alone",
             "Anything that already existed - iptables you had installed, IP "
             "forwarding you had already enabled - is marked as pre-existing "
             "and is never touched."),
            ("It shreds keys rather than deleting them",
             "Private keys are overwritten before being unlinked. On SSDs and "
             "copy-on-write filesystems the controller may still keep the "
             "original block, so full-disk encryption is the only real "
             "guarantee - we do not pretend otherwise."),
        ]:
            block = QVBoxLayout()
            block.setSpacing(1)
            h = QLabel(title)
            h.setObjectName("H3")
            block.addWidget(h)
            block.addWidget(muted(body))
            explain.add_layout(block)
        self.add(explain)

        self.options = Card("What to remove")
        self.engine_boxes: Dict[str, QCheckBox] = {}
        self.engine_holder = QVBoxLayout()
        self.options.add_layout(self.engine_holder)
        self.options.add(hline())
        self.keep_packages = QCheckBox(
            "Keep the installed packages (remove configuration only)")
        self.keep_hardening = QCheckBox(
            "Keep the hardening settings (fail2ban, sysctl, SSH policy)")
        self.keep_backups = QCheckBox(
            "Keep /etc/tessera and its state backups")
        for box in (self.keep_packages, self.keep_hardening, self.keep_backups):
            self.options.add(box)
        self.add(self.options)

        row = QHBoxLayout()
        self.preview_btn = QPushButton("Preview what will be removed")
        self.preview_btn.clicked.connect(self._preview)
        self.remove_btn = QPushButton("Remove")
        self.remove_btn.setObjectName("Danger")
        self.remove_btn.clicked.connect(self._remove)
        row.addWidget(self.preview_btn)
        row.addWidget(self.remove_btn)
        row.addStretch(1)
        self.col.addLayout(row)

        self.plan_card = Card("Removal plan")
        self.plan_body = QVBoxLayout()
        self.plan_card.add_layout(self.plan_body)
        self.plan_card.hide()
        self.add(self.plan_card)

        self.progress = QProgressBar()
        self.progress.hide()
        self.add(self.progress)
        self.stretch()

    def set_session(self, session: Session) -> None:
        self.session = session
        clear_layout(self.engine_holder)
        self.engine_boxes = {}
        installed = session.state.installed_engines
        if not installed:
            self.engine_holder.addWidget(muted(
                "Nothing here was installed by Tessera. If you set a VPN up by "
                "hand, Tessera cannot know what it touched and will not guess."))
            self.remove_btn.setEnabled(False)
            self.preview_btn.setEnabled(False)
            return
        self.remove_btn.setEnabled(True)
        self.preview_btn.setEnabled(True)
        for name in installed:
            box = QCheckBox(branding.ENGINE_LABELS.get(name, name))
            box.setChecked(True)
            self.engine_boxes[name] = box
            self.engine_holder.addWidget(box)

    def _selected(self) -> List[str]:
        return [n for n, b in self.engine_boxes.items() if b.isChecked()]

    def _options(self) -> Dict:
        return {"purge_packages": not self.keep_packages.isChecked(),
                "keep_backups": self.keep_backups.isChecked(),
                "remove_hardening": not self.keep_hardening.isChecked()}

    def _preview(self) -> None:
        if not self.session or not self._selected():
            return
        self._worker = PlanWorker(self.session, self.session.spec_from_state(),
                                  "uninstall", self._selected(), self._options())
        self._worker.done.connect(self._show_plan)
        self._worker.failed.connect(
            lambda m, r: QMessageBox.critical(self, "Error", m))
        self._worker.start()

    def _show_plan(self, plan: Plan) -> None:
        clear_layout(self.plan_body)
        self._rows = []
        for i, step in enumerate(plan.steps, 1):
            row = StepRow(i, len(plan.steps), step.title, step.why,
                          step.preview())
            self._rows.append(row)
            self.plan_body.addWidget(row)
        for note in plan.notes:
            self.plan_body.addWidget(muted(note))
        self.plan_card.show()

    def _remove(self) -> None:
        targets = self._selected()
        if not self.session or not targets:
            return
        typed, ok = QInputDialog.getText(
            self, "Confirm removal",
            "This removes {} from {} and shreds its keys.\n\n"
            "Type REMOVE to confirm:".format(
                " and ".join(targets), self.session.target.display()))
        if not ok or typed.strip() != "REMOVE":
            return
        self.remove_btn.setEnabled(False)
        self.progress.show()
        self._worker = ExecuteWorker(self.session,
                                     self.session.spec_from_state(),
                                     "uninstall", targets, self._options())
        self._worker.progress.connect(self._on_step)
        self._worker.done.connect(self._done)
        self._worker.failed.connect(
            lambda m, r: (self.remove_btn.setEnabled(True),
                          QMessageBox.critical(self, "Error", m)))
        self._worker.start()

    def _on_step(self, index: int, total: int, title: str, state: str) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(index)
        if index <= len(self._rows):
            self._rows[index - 1].set_state(state)

    def _done(self, report, _configs) -> None:
        self.remove_btn.setEnabled(True)
        if report.succeeded:
            QMessageBox.information(
                self, "Removed",
                "Removed cleanly in {:.0f} seconds.\n\nClient configuration "
                "files on this computer are untouched - delete those yourself."
                .format(report.duration))
        else:
            QMessageBox.warning(
                self, "Removal incomplete",
                "Stopped at: {}\n\nRe-run to continue; the inventory still "
                "records what is left.".format(
                    report.failed_step.title if report.failed_step else "?"))
        self.removed.emit()


# --------------------------------------------------------------------------- #
# Window
# --------------------------------------------------------------------------- #
class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("{} - {}".format(branding.NAME, branding.TAGLINE))
        self.resize(1180, 800)
        self.setMinimumSize(940, 640)
        self.session: Optional[Session] = None

        root = QWidget()
        root.setObjectName("Root")
        row = QHBoxLayout(root)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        # -- sidebar -------------------------------------------------------
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(216)
        col = QVBoxLayout(side)
        col.setContentsMargins(16, 20, 12, 16)
        col.setSpacing(4)
        col.addWidget(Wordmark(__version__))
        col.addSpacing(18)

        self.nav_buttons: Dict[str, QPushButton] = {}
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for i, name in enumerate(PAGES):
            btn = QPushButton(name)
            btn.setObjectName("NavItem")
            btn.setCheckable(True)
            btn.setChecked(i == 0)
            btn.clicked.connect(lambda _, n=name: self.show_page(n))
            self.nav_group.addButton(btn)
            self.nav_buttons[name] = btn
            col.addWidget(btn)
        col.addStretch(1)

        self.footer = QLabel("Not connected")
        self.footer.setObjectName("Why")
        self.footer.setWordWrap(True)
        col.addWidget(self.footer)
        row.addWidget(side)

        # -- pages ---------------------------------------------------------
        self.stack = QStackedWidget()
        self.connect_page = ConnectPage()
        self.install_page = InstallPage()
        self.dashboard_page = DashboardPage()
        self.peers_page = PeersPage()
        self.audit_page = AuditPage()
        self.remove_page = RemovePage()
        self.pages = {
            "Connect": self.connect_page, "Install": self.install_page,
            "Dashboard": self.dashboard_page, "Devices": self.peers_page,
            "Audit": self.audit_page, "Remove": self.remove_page,
        }
        for page in self.pages.values():
            self.stack.addWidget(page)
        row.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.connect_page.connected.connect(self._on_connected)
        self.install_page.installed.connect(self._on_changed)
        self.remove_page.removed.connect(self._on_changed)
        self._set_enabled(False)

    def _set_enabled(self, on: bool) -> None:
        for name, btn in self.nav_buttons.items():
            if name != "Connect":
                btn.setEnabled(on)

    def show_page(self, name: str) -> None:
        self.stack.setCurrentWidget(self.pages[name])
        self.nav_buttons[name].setChecked(True)

    def _on_connected(self, session: Session) -> None:
        self.session = session
        for page in (self.install_page, self.dashboard_page, self.peers_page,
                     self.audit_page, self.remove_page):
            page.set_session(session)
        self._set_enabled(True)
        self.footer.setText("{}\n{}".format(session.target.display(),
                                            summary_line(session.state)))
        self.show_page("Dashboard" if session.state.installed_engines
                       else "Install")

    def _on_changed(self) -> None:
        if not self.session:
            return
        try:
            self.session.refresh()
        except Exception:                                      # noqa: BLE001
            pass
        self._on_connected(self.session)


def main(argv: Optional[List[str]] = None) -> int:
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(branding.NAME)
    app.setApplicationVersion(__version__)
    theme.apply_palette(app)
    app.setStyleSheet(theme.stylesheet())
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

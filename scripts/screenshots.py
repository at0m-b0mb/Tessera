#!/usr/bin/env python3
"""Render the GUI to PNGs without a display.

Runs the real application against the demo server, so the screenshots show
genuine rendered output rather than a mockup that will drift from the code.

    QT_QPA_PLATFORM=offscreen python3 scripts/screenshots.py assets/screenshots
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QScrollArea

from tessera.core import interview as iv
from tessera.core.manager import Session
from tessera.core.models import InstallSpec, Target
from tessera.gui import theme
from tessera.gui.app import ClientConfigDialog, MainWindow

SCALE = 2  # retina


def settle(app, rounds: int = 6) -> None:
    for _ in range(rounds):
        app.processEvents()


def grab(widget, path: str) -> None:
    settle(QApplication.instance())
    pix = widget.grab()
    pix.save(path)
    print("  {:44} {}x{}".format(os.path.basename(path),
                                 pix.width(), pix.height()))


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "assets/screenshots"
    os.makedirs(outdir, exist_ok=True)

    app = QApplication(sys.argv)
    theme.apply_palette(app)
    app.setStyleSheet(theme.stylesheet())

    win = MainWindow()
    win.resize(1180, 800)
    win.show()
    settle(app)
    grab(win, os.path.join(outdir, "01-connect.png"))

    # Connect to the simulated server, synchronously.
    session = Session.connect(Target(host="demo", label="demo server"))
    win._on_connected(session)
    settle(app)
    win.show_page("Install")
    settle(app)
    grab(win, os.path.join(outdir, "02-install.png"))

    # Show a compiled plan.
    page = win.install_page
    page.spec.engines = ["wireguard"]
    iv.mark_answered(page.spec, "engines")
    iv.fill_defaults(page.spec, session.facts)
    plan, _ = session.build_install_plan(page.spec)
    page._show_plan(plan)
    settle(app)
    # Scroll to the plan itself; it is the whole point of this screenshot.
    area = page.findChild(QScrollArea)
    if area is not None:
        # Put the top of the plan card at the top of the viewport, rather than
        # scrolling to the very bottom where the page's trailing stretch is.
        top = page.plan_card.mapTo(area.widget(), page.plan_card.rect().topLeft())
        area.verticalScrollBar().setValue(max(0, top.y() - 12))
        settle(app)
    grab(win, os.path.join(outdir, "03-plan.png"))
    if area is not None:
        area.verticalScrollBar().setValue(0)

    # Actually install on the demo, then show the rest.
    spec = InstallSpec(target=session.target)
    spec.engines = ["wireguard", "openvpn"]
    iv.mark_answered(spec, "engines")
    spec.first_peer = "work-laptop"
    iv.mark_answered(spec, "first_peer")
    iv.fill_defaults(spec, session.facts)
    report, configs = session.install(spec)
    print("  demo install:", "ok" if report.succeeded else "FAILED")
    for name in ("phone", "tablet"):
        session.add_peer("wireguard", name)

    win._on_connected(session)
    settle(app)
    win.show_page("Dashboard")
    win.dashboard_page._render(session.status())
    settle(app)
    grab(win, os.path.join(outdir, "04-dashboard.png"))

    win.show_page("Devices")
    win.peers_page.reload()
    settle(app)
    grab(win, os.path.join(outdir, "05-devices.png"))

    win.show_page("Audit")
    win.audit_page._render(session.audit())
    settle(app)
    grab(win, os.path.join(outdir, "06-audit.png"))

    win.show_page("Remove")
    plan = session.build_uninstall_plan()
    win.remove_page._show_plan(plan)
    settle(app)
    grab(win, os.path.join(outdir, "07-remove.png"))

    if configs:
        dialog = ClientConfigDialog(configs, win)
        dialog.resize(780, 560)
        dialog.show()
        settle(app)
        grab(dialog, os.path.join(outdir, "08-client-config.png"))
        dialog.close()

    print("\nWrote screenshots to {}".format(outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())

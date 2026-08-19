#!/usr/bin/env python3
"""Rasterise the brand SVGs.

GitHub needs PNG for the social preview card, and a PNG in the README renders
identically everywhere instead of depending on which fonts the viewer happens
to have installed. The SVGs stay the source of truth; these are generated.

    QT_QPA_PLATFORM=offscreen python3 scripts/render_png.py assets
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QImage, QPainter
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import QApplication

from tessera import branding

# (source svg, output png, width, height, scale)
JOBS = [
    ("banner.svg", "banner.png", 1280, 360, 2),
    ("logo.svg", "logo.png", 256, 256, 2),
    ("icon.svg", "icon.png", 128, 128, 4),
    ("wordmark.svg", "wordmark.png", 640, 160, 2),
]


def render(src: str, dst: str, w: int, h: int, scale: int = 2,
           background: str = branding.INK) -> None:
    renderer = QSvgRenderer(src)
    if not renderer.isValid():
        raise SystemExit("cannot read {}".format(src))
    img = QImage(w * scale, h * scale, QImage.Format.Format_ARGB32)
    img.fill(QColor(background))
    painter = QPainter(img)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    renderer.render(painter, QRectF(0, 0, w * scale, h * scale))
    painter.end()
    img.save(dst)
    print("  {:20} {}x{}".format(os.path.basename(dst), img.width(), img.height()))


def social_preview(outdir: str) -> None:
    """GitHub's card is 1280x640 and gets cropped hard on small surfaces.

    So this is not the banner stretched: the mark and wordmark are re-composed
    with the safe area in mind, and nothing important sits near an edge.
    """
    w, h = 1280, 640
    scale = 2
    img = QImage(w * scale, h * scale, QImage.Format.Format_ARGB32)
    img.fill(QColor(branding.INK))
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(scale, scale)

    # A soft bronze wash behind the mark, so the card is not a flat black box.
    from PyQt6.QtGui import QRadialGradient
    glow = QRadialGradient(w * 0.5, h * 0.42, w * 0.45)
    glow.setColorAt(0.0, QColor(200, 138, 74, 46))
    glow.setColorAt(1.0, QColor(11, 13, 16, 0))
    p.fillRect(0, 0, w, h, glow)

    mark = QSvgRenderer(os.path.join(outdir, "logo.svg"))
    size = 172
    mark.render(p, QRectF((w - size) / 2.0, 118, size, size))

    from PyQt6.QtGui import QFont
    title = QFont("Inter", 68, QFont.Weight.Bold)
    title.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 7)
    p.setFont(title)
    p.setPen(QColor(branding.BONE))
    p.drawText(QRectF(0, 322, w, 92), Qt.AlignmentFlag.AlignHCenter, "TESSERA")

    p.setFont(QFont("Inter", 23))
    p.setPen(QColor(branding.BRONZE_HI))
    p.drawText(QRectF(0, 412, w, 40), Qt.AlignmentFlag.AlignHCenter,
               branding.TAGLINE)

    p.setFont(QFont("Inter", 19))
    p.setPen(QColor(branding.BONE_DIM))
    p.drawText(QRectF(0, 468, w, 34), Qt.AlignmentFlag.AlignHCenter,
               "WireGuard  ·  OpenVPN  ·  Tailscale")

    p.setFont(QFont("Inter", 16))
    p.setPen(QColor(branding.MUTED))
    p.drawText(QRectF(0, 510, w, 30), Qt.AlignmentFlag.AlignHCenter,
               "Install, configure and remove them cleanly — from any desktop.")

    # A hairline rule in the accent, bottom-anchored, to frame the card.
    p.fillRect(QRectF(0, h - 6, w, 6), QColor(branding.BRONZE))
    p.end()

    dst = os.path.join(outdir, "social-preview.png")
    img.save(dst)
    print("  {:20} {}x{}".format("social-preview.png", img.width(), img.height()))


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "assets"
    app = QApplication(sys.argv)
    for src, dst, w, h, scale in JOBS:
        render(os.path.join(outdir, src), os.path.join(outdir, dst), w, h, scale)
    social_preview(outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

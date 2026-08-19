#!/usr/bin/env python3
"""Generate the brand assets.

The SVG mark is built from the same fracture coordinates the Qt widget paints,
imported from the widget module, so the icon in the README and the logo in the
running application can never drift apart.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tessera import branding

# Imported rather than duplicated: one source of truth for the shape.
FRACTURE = [(0.50, 0.00), (0.63, 0.15), (0.38, 0.29), (0.66, 0.45),
            (0.35, 0.59), (0.62, 0.73), (0.40, 0.87), (0.50, 1.00)]


def _halves(size: float, gap: float, inset: float = 0.0):
    w = h = size - inset * 2
    ox = oy = inset
    g = w * gap
    left = ["M {:.2f} {:.2f}".format(ox, oy)]
    for fx, fy in FRACTURE:
        left.append("L {:.2f} {:.2f}".format(ox + fx * w - g / 2, oy + fy * h))
    left.append("L {:.2f} {:.2f} Z".format(ox, oy + h))
    right = ["M {:.2f} {:.2f}".format(ox + w, oy)]
    for fx, fy in FRACTURE:
        right.append("L {:.2f} {:.2f}".format(ox + fx * w + g / 2, oy + fy * h))
    right.append("L {:.2f} {:.2f} Z".format(ox + w, oy + h))
    return " ".join(left), " ".join(right)


def mark(size: int = 256, gap: float = 0.10, rounded: bool = False) -> str:
    left, right = _halves(size, gap)
    radius = ' rx="{}"'.format(int(size * 0.18)) if rounded else ""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" \
width="{size}" height="{size}" role="img" aria-label="Tessera">
  <title>Tessera</title>
  <defs>
    <linearGradient id="l" x1="0" y1="0" x2="0.6" y2="1">
      <stop offset="0" stop-color="{branding.BRONZE_HI}"/>
      <stop offset="1" stop-color="{branding.BRONZE}"/>
    </linearGradient>
    <linearGradient id="r" x1="0.4" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{branding.BRONZE_DIM}"/>
      <stop offset="1" stop-color="#5E4022"/>
    </linearGradient>
  </defs>
  <rect width="{size}" height="{size}"{radius} fill="{branding.INK}"/>
  <path d="{left}" fill="url(#l)"/>
  <path d="{right}" fill="url(#r)"/>
</svg>
'''


def wordmark(width: int = 640) -> str:
    m = 88
    pad = 40
    left, right = _halves(m, 0.10)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 160" \
width="{width}" height="160" role="img" aria-label="Tessera - {branding.TAGLINE}">
  <title>Tessera</title>
  <defs>
    <linearGradient id="l" x1="0" y1="0" x2="0.6" y2="1">
      <stop offset="0" stop-color="{branding.BRONZE_HI}"/>
      <stop offset="1" stop-color="{branding.BRONZE}"/>
    </linearGradient>
    <linearGradient id="r" x1="0.4" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{branding.BRONZE_DIM}"/>
      <stop offset="1" stop-color="#5E4022"/>
    </linearGradient>
  </defs>
  <rect width="{width}" height="160" fill="{branding.INK}"/>
  <g transform="translate({pad},36)">
    <path d="{left}" fill="url(#l)"/>
    <path d="{right}" fill="url(#r)"/>
  </g>
  <text x="{pad + m + 28}" y="82" font-family="Inter, Segoe UI, Helvetica, sans-serif"
        font-size="46" font-weight="700" letter-spacing="3" fill="{branding.BONE}">TESSERA</text>
  <text x="{pad + m + 30}" y="112" font-family="Inter, Segoe UI, Helvetica, sans-serif"
        font-size="17" fill="{branding.MUTED}">{branding.TAGLINE}</text>
</svg>
'''


def banner(width: int = 1280, height: int = 360) -> str:
    """Repository social banner."""
    m = 150
    left, right = _halves(m, 0.10)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" \
width="{width}" height="{height}">
  <defs>
    <linearGradient id="l" x1="0" y1="0" x2="0.6" y2="1">
      <stop offset="0" stop-color="{branding.BRONZE_HI}"/>
      <stop offset="1" stop-color="{branding.BRONZE}"/>
    </linearGradient>
    <linearGradient id="r" x1="0.4" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{branding.BRONZE_DIM}"/>
      <stop offset="1" stop-color="#5E4022"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.28" cy="0.5" r="0.6">
      <stop offset="0" stop-color="{branding.BRONZE}" stop-opacity="0.16"/>
      <stop offset="1" stop-color="{branding.INK}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="{width}" height="{height}" fill="{branding.INK}"/>
  <rect width="{width}" height="{height}" fill="url(#glow)"/>
  <g transform="translate(120,{(height - m) // 2})">
    <path d="{left}" fill="url(#l)"/>
    <path d="{right}" fill="url(#r)"/>
  </g>
  <text x="330" y="{height // 2 - 34}" font-family="Inter, Segoe UI, Helvetica, sans-serif"
        font-size="66" font-weight="700" letter-spacing="5" fill="{branding.BONE}">TESSERA</text>
  <text x="333" y="{height // 2 + 6}" font-family="Inter, Segoe UI, Helvetica, sans-serif"
        font-size="23" fill="{branding.BRONZE_HI}">{branding.TAGLINE}</text>
  <text x="333" y="{height // 2 + 46}" font-family="Inter, Segoe UI, Helvetica, sans-serif"
        font-size="18" fill="{branding.MUTED}">WireGuard &#183; OpenVPN &#183; Tailscale</text>
  <text x="333" y="{height // 2 + 76}" font-family="Inter, Segoe UI, Helvetica, sans-serif"
        font-size="16" fill="{branding.MUTED}">Install, configure and remove them cleanly - from any desktop.</text>
</svg>
'''


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "assets"
    os.makedirs(outdir, exist_ok=True)
    files = {
        "logo.svg": mark(256),
        "icon.svg": mark(128, rounded=True),
        "wordmark.svg": wordmark(),
        "banner.svg": banner(),
    }
    for name, body in files.items():
        path = os.path.join(outdir, name)
        with open(path, "w") as fh:
            fh.write(body)
        print("  {:16} {:>6} bytes".format(name, len(body)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

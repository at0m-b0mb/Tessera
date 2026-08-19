"""QR codes for client configs.

Typing a WireGuard config into a phone by hand is how people end up with a
tunnel that does not work and no idea which character they got wrong.  The
official apps on iOS and Android both scan a QR code of the whole config file,
so that is what we render.

We do it locally rather than shelling out to ``qrencode`` on the server, which
matters: the config contains the client's private key, and sending it to the
server to be drawn would undo the entire point of generating it here.

Two renderers, both pure Python:
  * ``terminal`` uses half-block characters so a 33x33 code fits in 17 rows -
    small enough to actually show in a terminal without scrolling.
  * ``svg`` produces a scalable code for the GUI and for saving.
"""

from __future__ import annotations

from typing import List

try:
    import qrcode
    _HAVE_QRCODE = True
except Exception:                                              # pragma: no cover
    _HAVE_QRCODE = False


class QRUnavailable(RuntimeError):
    pass


def matrix(data: str, border: int = 2) -> List[List[bool]]:
    """Return the QR modules as a grid of booleans (True = dark)."""
    if not _HAVE_QRCODE:
        raise QRUnavailable(
            "the 'qrcode' package is required to render QR codes")
    # Error correction L: the config is long, and a phone screen held still
    # does not need the redundancy that would force a larger, denser code.
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L,
                      border=border, box_size=1)
    q.add_data(data)
    q.make(fit=True)
    return [[bool(cell) for cell in row] for row in q.get_matrix()]


def terminal(data: str, border: int = 2, invert: bool = False) -> str:
    """Render for a terminal, two rows of modules per line of text.

    Scanners need dark modules on a light background.  Most terminals are dark,
    so by default we draw the *background* light and the modules dark, which is
    the opposite of what looks natural in a dark terminal but is the thing that
    actually scans.
    """
    grid = matrix(data, border=border)
    if invert:
        grid = [[not c for c in row] for row in grid]
    # Pad to an even number of rows so the last line has a bottom half.
    if len(grid) % 2:
        grid.append([False] * len(grid[0]))

    lines: List[str] = []
    for y in range(0, len(grid), 2):
        top, bottom = grid[y], grid[y + 1]
        row = []
        for x in range(len(top)):
            t, b = top[x], bottom[x]
            # Dark module -> filled; light -> empty.
            if t and b:
                row.append("█")      # full block
            elif t:
                row.append("▀")      # upper half
            elif b:
                row.append("▄")      # lower half
            else:
                row.append(" ")
        lines.append("".join(row))
    return "\n".join(lines)


def svg(data: str, size: int = 320, border: int = 2,
        dark: str = "#0B0D10", light: str = "#FFFFFF") -> str:
    """Render as a standalone SVG, one path for every dark module."""
    grid = matrix(data, border=border)
    n = len(grid)
    scale = size / n
    rects = []
    for y, row in enumerate(grid):
        x = 0
        while x < n:
            if not row[x]:
                x += 1
                continue
            run = x
            while run < n and row[run]:
                run += 1
            # Merge horizontal runs into one rect: far fewer elements, and the
            # seams between adjacent squares stop showing at fractional scales.
            rects.append(
                '<rect x="{:.3f}" y="{:.3f}" width="{:.3f}" height="{:.3f}"/>'
                .format(x * scale, y * scale, (run - x) * scale, scale))
            x = run
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" '
            'viewBox="0 0 {s} {s}" shape-rendering="crispEdges">'
            '<rect width="{s}" height="{s}" fill="{light}"/>'
            '<g fill="{dark}">{body}</g></svg>').format(
                s=size, light=light, dark=dark, body="".join(rects))


def png_bytes(data: str, box_size: int = 8, border: int = 2) -> bytes:
    """PNG for saving to disk.  Requires Pillow."""
    if not _HAVE_QRCODE:
        raise QRUnavailable("the 'qrcode' package is required")
    import io
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L,
                      border=border, box_size=box_size)
    q.add_data(data)
    q.make(fit=True)
    buf = io.BytesIO()
    q.make_image(fill_color="black", back_color="white").save(buf, format="PNG")
    return buf.getvalue()


def available() -> bool:
    return _HAVE_QRCODE

"""Terminal presentation.

Rich if it is installed, plain ANSI if not.  The fallback is not a token
gesture - a VPN installer gets run over SSH on a fresh box where pip has never
been used, and "please install a dependency before you can read the output" is
a bad first impression.  Everything here degrades to something readable.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import List, Sequence, Tuple

from .. import branding

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
    _HAVE_RICH = True
except Exception:                                              # pragma: no cover
    _HAVE_RICH = False

# ANSI fallbacks, used when rich is missing.
_A = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "bronze": "\033[38;5;179m", "amber": "\033[38;5;215m",
    "ok": "\033[38;5;114m", "warn": "\033[38;5;215m",
    "fail": "\033[38;5;203m", "info": "\033[38;5;110m",
    "muted": "\033[38;5;244m",
}

THEME = {
    "brand": "bold #C88A4A",
    "accent": "#E0A868",
    "muted": "#6B7280",
    "ok": "#5BC98C",
    "warn": "#F0B454",
    "fail": "#E0575B",
    "info": "#7FA8D4",
    "step": "#A8A399",
    "wireguard": branding.ENGINE_COLORS["wireguard"],
    "openvpn": branding.ENGINE_COLORS["openvpn"],
    "tailscale": branding.ENGINE_COLORS["tailscale"],
}

_MARKS = {"pass": "+", "ok": "+", "warn": "!", "fail": "x", "info": "i",
          "skip": "-", "run": ">"}


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TESSERA_NO_COLOR"):
        return False
    return sys.stdout.isatty()


class UI:
    """Everything the CLI prints goes through here."""

    def __init__(self, quiet: bool = False, no_color: bool = False) -> None:
        self.quiet = quiet
        self.color = _color_enabled() and not no_color
        self.console = None
        if _HAVE_RICH:
            # soft_wrap: let the terminal wrap long shell commands instead of
            # rich reflowing them, which mangles indentation.
            # markup is disabled per-call in out(); step titles legitimately
            # contain things like "[packa]" that rich would otherwise eat.
            self.console = Console(
                theme=Theme(THEME), no_color=not self.color,
                highlight=False, soft_wrap=True)

    # -- primitives ------------------------------------------------------------
    def out(self, text: str = "", style: str = "") -> None:
        if self.quiet:
            return
        if self.console is not None:
            self.console.print(text, style=style or None, markup=False)
        else:
            prefix = _A.get(style, "") if self.color else ""
            suffix = _A["reset"] if prefix else ""
            print("{}{}{}".format(prefix, text, suffix))

    def rule(self, label: str = "") -> None:
        if self.quiet:
            return
        width = shutil.get_terminal_size((80, 24)).columns
        if self.console is not None:
            self.console.rule(label, style="muted")
        else:
            bar = "-" * max(0, width - len(label) - 4)
            print("-- {} {}".format(label, bar) if label else "-" * width)

    def banner(self, version: str, subtitle: str = "") -> None:
        if self.quiet:
            return
        if self.console is not None:
            art = Text(branding.ASCII_LOGO.strip("\n"), style="brand")
            self.console.print(art)
            self.console.print("  {}".format(branding.TAGLINE), style="accent")
            self.console.print("  v{}{}".format(
                version, "  -  " + subtitle if subtitle else ""), style="muted")
            self.console.print()
        else:
            print(branding.banner(version))

    # -- semantic --------------------------------------------------------------
    def ok(self, text: str) -> None:
        self._tagged("ok", text, "ok")

    def warn(self, text: str) -> None:
        self._tagged("warn", text, "warn")

    def fail(self, text: str) -> None:
        self._tagged("fail", text, "fail")

    def info(self, text: str) -> None:
        self._tagged("info", text, "info")

    def note(self, text: str) -> None:
        self.out("  " + text, "muted")

    def _tagged(self, mark: str, text: str, style: str) -> None:
        if self.quiet and style in ("ok", "info"):
            return
        symbol = _MARKS.get(mark, "*")
        if self.console is not None:
            self.console.print(symbol, style=style, end=" ", markup=False)
            self.console.print(text, markup=False)
        else:
            c = _A.get(style, "") if self.color else ""
            r = _A["reset"] if c else ""
            print("{}{}{} {}".format(c, symbol, r, text))

    def error(self, exc: Exception) -> None:
        """Errors go to stderr and always print, even when quiet."""
        message = getattr(exc, "message", None) or str(exc)
        remedy = getattr(exc, "remedy", "")
        stream = sys.stderr
        if self.console is not None:
            err = Console(stderr=True, theme=Theme(THEME),
                          no_color=not self.color, highlight=False)
            err.print("x", style="fail", end=" ", markup=False)
            err.print(message, markup=False)
            if remedy:
                err.print("  " + remedy, style="muted", markup=False)
        else:
            print("x {}".format(message), file=stream)
            if remedy:
                print("  {}".format(remedy), file=stream)

    # -- structures ------------------------------------------------------------
    def kv(self, pairs: Sequence[Tuple[str, str]], indent: int = 2) -> None:
        if self.quiet or not pairs:
            return
        width = max(len(k) for k, _ in pairs)
        for k, v in pairs:
            label = k.ljust(width)
            if self.console is not None:
                self.console.print(
                    "{}{}  ".format(" " * indent, label), style="muted",
                    end="", markup=False)
                self.console.print(str(v), markup=False)
            else:
                print("{}{}  {}".format(" " * indent, label, v))

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]],
              title: str = "") -> None:
        if self.quiet:
            return
        if not rows:
            self.note("(none)")
            return
        if self.console is not None:
            t = Table(title=title or None, header_style="brand",
                      border_style="muted", show_edge=False, pad_edge=False)
            for h in headers:
                t.add_column(h)
            for row in rows:
                # Wrap in Text so rich does not parse cell contents as markup.
                # Cells hold user data - a device named "[test]" would
                # otherwise vanish, or worse, restyle the rest of the table.
                t.add_row(*[Text(str(c)) for c in row])
            self.console.print(t)
            return
        widths = [max(len(str(headers[i])),
                      max((len(str(r[i])) for r in rows), default=0))
                  for i in range(len(headers))]
        print("  " + "  ".join(str(h).ljust(widths[i])
                               for i, h in enumerate(headers)))
        print("  " + "  ".join("-" * w for w in widths))
        for row in rows:
            print("  " + "  ".join(str(c).ljust(widths[i])
                                   for i, c in enumerate(row)))

    def panel(self, body: str, title: str = "", style: str = "brand") -> None:
        if self.quiet:
            return
        if self.console is not None:
            self.console.print(Panel(Text(body), title=title or None,
                                     border_style=style, padding=(1, 2)))
        else:
            self.rule(title)
            print(body)
            self.rule()

    def block(self, text: str) -> None:
        """Print verbatim, no wrapping or markup - for configs and QR codes."""
        if self.quiet:
            return
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        sys.stdout.flush()

    # -- input -----------------------------------------------------------------
    def ask(self, prompt: str, default: str = "",
            secret: bool = False) -> str:
        suffix = " [{}]".format(default) if default not in ("", None) else ""
        text = "{}{}: ".format(prompt, suffix)
        if secret:
            import getpass
            value = getpass.getpass(text)
        else:
            if self.console is not None:
                # markup=False is essential here: the default is shown as
                # "[laptop]", which rich would otherwise parse as a style tag
                # and silently swallow, hiding every default from the user.
                self.console.print(text, end="", markup=False)
                value = input()
            else:
                value = input(text)
        return value.strip() or str(default)

    def confirm(self, prompt: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            raw = self.ask("{} ({})".format(prompt, hint), "").strip().lower()
            if not raw:
                return default
            if raw in ("y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            self.note("Please answer y or n.")

    def choose(self, prompt: str, options: Sequence[Tuple[str, str]],
               default: str = "") -> str:
        self.out("  " + prompt, "bold")
        for i, (value, label) in enumerate(options, 1):
            marker = " (default)" if value == default else ""
            self.out("    {}) {}{}".format(i, label, marker))
        while True:
            raw = self.ask("  Choose [1-{}]".format(len(options)), "")
            if not raw and default:
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return options[int(raw) - 1][0]
            for value, _ in options:
                if raw == value:
                    return value
            self.note("Enter a number between 1 and {}.".format(len(options)))

    def multichoose(self, prompt: str, options: Sequence[Tuple[str, str]],
                    default: Sequence[str] = ()) -> List[str]:
        self.out("  " + prompt, "bold")
        for i, (value, label) in enumerate(options, 1):
            mark = "*" if value in default else " "
            self.out("    [{}] {}) {}".format(mark, i, label))
        hint = ",".join(str(i + 1) for i, (v, _) in enumerate(options)
                        if v in default)
        while True:
            raw = self.ask("  Choose (comma-separated)", hint)
            picks: List[str] = []
            for part in raw.replace(" ", ",").split(","):
                part = part.strip()
                if not part:
                    continue
                if part.isdigit() and 1 <= int(part) <= len(options):
                    picks.append(options[int(part) - 1][0])
                else:
                    match = [v for v, _ in options if v == part]
                    if match:
                        picks.append(match[0])
            if picks:
                seen: List[str] = []
                for p in picks:
                    if p not in seen:
                        seen.append(p)
                return seen
            self.note("Pick at least one.")


def engine_style(name: str) -> str:
    return name if name in branding.ENGINE_COLORS else "brand"


def human_bytes(n: int) -> str:
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < step:
            return "{:.0f} {}".format(n, unit) if unit == "B" else \
                   "{:.1f} {}".format(n, unit)
        n /= step
    return "{:.1f} PiB".format(n)


def human_age(epoch: int) -> str:
    import time
    if not epoch:
        return "never"
    delta = int(time.time()) - int(epoch)
    if delta < 60:
        return "{}s ago".format(delta)
    if delta < 3600:
        return "{}m ago".format(delta // 60)
    if delta < 86400:
        return "{}h ago".format(delta // 3600)
    return "{}d ago".format(delta // 86400)

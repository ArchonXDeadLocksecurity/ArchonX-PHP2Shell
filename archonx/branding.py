"""ArchonX branding — solid-colour banner, phase-aware palette, timestamped fields.

Design rules (locked):
  1. Always verbose. There is no -v flag. Every field prints.
  2. Every log line starts with [HH:MM:SS.mmm].
  3. Banner is solid hacker-green on colour terminals, plain otherwise.
  4. Runtime palette is phase-aware: green for discovery phases 0-2,
     red (DeadLock) for the exploitation phase 3 and shell phase 4.
  5. NO_COLOR / FORCE_COLOR env vars honoured. No --theme flag.

Standard library only. Importable even if the rest of the package is broken.
"""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime

# ─── identity ────────────────────────────────────────────────────────────
VERSION = "1.0.0"
TOOL_NAME = "ArchonX-PHP2Shell"
BRAND_NAME = "ArchonX_DeadLock_Security"
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")

# ─── markers ─────────────────────────────────────────────────────────────
MARK_OK = "✓"
MARK_FAIL = "✗"
MARK_ARROW = "→"
MARK_DOT = "·"
MARK_WARN = "⚠"
MARK_ELLIPSIS = "…"
MARK_HR = "═"
MARK_RULE = "─"

# ─── ANSI ────────────────────────────────────────────────────────────────
RESET = "\x1b[0m"
BOLD = "\x1b[1m"

# ─── banner ──────────────────────────────────────────────────────────────
BANNER_ART = r"""
 █████╗ ██████╗  ██████╗██╗  ██╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗████╗  ██║╚██╗██╔╝
███████║██████╔╝██║     ███████║██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██║██╔══██╗██║     ██╔══██║██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║██║  ██║╚██████╗██║  ██║╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
"""

# ─── colour detection ────────────────────────────────────────────────────
def _use_color() -> bool:
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


# ─── palettes ────────────────────────────────────────────────────────────
class Palette:
    __slots__ = ("name", "primary", "secondary", "accent",
                 "warning", "error", "dim", "timestamp")

    def __init__(self, name, primary, secondary, accent,
                 warning, error, dim, timestamp):
        self.name = name
        self.primary = primary
        self.secondary = secondary
        self.accent = accent
        self.warning = warning
        self.error = error
        self.dim = dim
        self.timestamp = timestamp


GREEN = Palette(
    name="green",
    primary="\x1b[38;5;46m",
    secondary="\x1b[38;5;34m",
    accent="\x1b[38;5;118m",
    warning="\x1b[38;5;220m",
    error="\x1b[38;5;196m",
    dim="\x1b[38;5;240m",
    timestamp="\x1b[38;5;28m",
)

RED = Palette(
    name="red",
    primary="\x1b[38;5;196m",
    secondary="\x1b[38;5;160m",
    accent="\x1b[38;5;208m",
    warning="\x1b[38;5;220m",
    error="\x1b[38;5;197m",
    dim="\x1b[38;5;240m",
    timestamp="\x1b[38;5;88m",
)

PLAIN = Palette(
    name="none",
    primary="", secondary="", accent="",
    warning="", error="", dim="", timestamp="",
)


def _initial_palette() -> Palette:
    return GREEN if _use_color() else PLAIN


# ─── state ───────────────────────────────────────────────────────────────
@dataclass
class _State:
    palette: Palette = field(default_factory=_initial_palette)
    t_start: float = field(default_factory=time.monotonic)
    t_phase: float = field(default_factory=time.monotonic)
    debug: bool = False


class Log:
    def __init__(self) -> None:
        self.state = _State()

    # ── configuration ────────────────────────────────────────────────
    def set_debug(self, on: bool) -> None:
        self.state.debug = on

    def set_palette(self, name: str) -> None:
        """Switch runtime palette. Called at phase transitions."""
        if name == "none" or not _use_color():
            self.state.palette = PLAIN
        elif name == "red":
            self.state.palette = RED
        elif name == "green":
            self.state.palette = GREEN

    def disable_color(self) -> None:
        os.environ["NO_COLOR"] = "1"
        self.state.palette = PLAIN

    # ── low level ────────────────────────────────────────────────────
    def _stamp(self) -> str:
        p = self.state.palette
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        return f"{p.timestamp}[{ts}]{RESET}"

    def _line(self, body: str) -> None:
        print(f"{self._stamp()} {body}", flush=True)

    def stream(self, text: str) -> None:
        """No newline, no timestamp — for progress indicators only."""
        sys.stdout.write(text)
        sys.stdout.flush()

    # ── banner ───────────────────────────────────────────────────────
    def banner(self, subtitle: bool = True) -> None:
        p = self.state.palette
        print(f"{p.primary}{BANNER_ART}{RESET}", end="")
        if subtitle:
            rule = MARK_RULE * len(BRAND_NAME)
            print(f"{p.secondary}              {BRAND_NAME}{RESET}")
            print(f"{p.secondary}              {rule}{RESET}")
            print(f"{p.dim}              {TOOL_NAME} v{VERSION}{RESET}")
            print(f"{p.dim}              {CVE_IDS[0]} / {CVE_IDS[1]}{RESET}")
            print(f"{p.dim}              authorized security testing only{RESET}")
        print(flush=True)

    # ── phases ───────────────────────────────────────────────────────
    def phase(self, title: str, num: int | None = None,
              palette: str | None = None) -> None:
        if palette:
            self.set_palette(palette)
        self.state.t_phase = time.monotonic()
        p = self.state.palette
        head = f"PHASE {num}: {title}" if num is not None else title.upper()
        width = max(8, 60 - len(head))
        bar = MARK_HR * width
        self._line(f"{p.primary}{BOLD}{MARK_HR * 3} {head} {bar}{RESET}")

    def phase_done(self, summary: str = "") -> None:
        elapsed = time.monotonic() - self.state.t_phase
        msg = f"phase complete ({elapsed:.2f}s)"
        if summary:
            msg += f" — {summary}"
        self.ok(msg)

    # ── messages ─────────────────────────────────────────────────────
    def info(self, msg: str) -> None:
        self._line(f"{self.state.palette.primary}{MARK_ARROW}{RESET} {msg}")

    def ok(self, msg: str) -> None:
        p = self.state.palette
        self._line(f"{p.accent}{MARK_OK}{RESET} {msg}")

    def warn(self, msg: str) -> None:
        p = self.state.palette
        self._line(f"{p.warning}{MARK_WARN}{RESET} {p.warning}{msg}{RESET}")

    def error(self, msg: str) -> None:
        p = self.state.palette
        self._line(f"{p.error}{MARK_FAIL} {msg}{RESET}")

    def debug(self, msg: str) -> None:
        if self.state.debug:
            p = self.state.palette
            self._line(f"{p.dim}{MARK_DOT} {msg}{RESET}")

    # ── field with dotted leader ────────────────────────────────────
    def field(self, name: str, value, status: str = "ok",
              width: int = 38) -> None:
        p = self.state.palette
        status_mark, status_colour = {
            "ok":   (MARK_OK,    p.accent),
            "fail": (MARK_FAIL,  p.error),
            "warn": (MARK_WARN,  p.warning),
            "":     ("",         ""),
        }.get(status, (MARK_OK, p.accent))

        vs = str(value)
        dots = "." * max(1, width - len(name) - len(vs) - 2)
        line = (
            f"{p.primary}{MARK_ARROW}{RESET} {name} "
            f"{p.dim}{dots}{RESET} {vs}"
        )
        if status_mark:
            line += f" {status_colour}{status_mark}{RESET}"
        self._line(line)

    # ── prompt ──────────────────────────────────────────────────────
    def prompt(self, cwd: str = "~") -> str:
        p = self.state.palette
        return f"{p.primary}archonx@target{RESET}:{p.dim}{cwd}${RESET} "

    # ── timings ─────────────────────────────────────────────────────
    def elapsed(self) -> float:
        return time.monotonic() - self.state.t_start

    # ── hexdump (only when debug) ───────────────────────────────────
    def hexdump(self, data: bytes, base: int = 0,
                width: int = 16, limit: int | None = None) -> None:
        if not self.state.debug:
            return
        p = self.state.palette
        buf = data if limit is None else data[:limit]
        for off in range(0, len(buf), width):
            chunk = buf[off:off + width]
            hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self._line(
                f"{p.dim}{base + off:08x}  {hexpart}  |{asc}|{RESET}"
            )
        if limit is not None and len(data) > limit:
            self._line(
                f"{p.dim}... ({len(data) - limit} bytes truncated){RESET}"
            )


# ─── singleton ───────────────────────────────────────────────────────────
log = Log()

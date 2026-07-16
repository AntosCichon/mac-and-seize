"""A minimal vi-like, read-only packet inspector built on stdlib ``curses``.

Shows one row per captured packet (timestamp, source, destination, top-level
layer) in a scrollable full-screen table. Navigation:

* Up / Down            move the selection
* PgUp / PgDn          move a screen at a time
* Home / End           jump to first / last
* Esc / Enter / q      leave the inspector

It is purely a viewer - nothing is modified - and it restores the terminal
cleanly on exit (via :func:`curses.wrapper`) so the REPL prompt returns intact.
"""

from __future__ import annotations

import curses
import sys

from mac_and_seize.core.errors import ModuleError

_COLUMNS = [
    ("timestamp", "timestamp", 10),
    ("interface", "interface", 12),
    ("source", "source", 30),
    ("destination", "destination", 30),
    ("layer", "layer", 12),
]
_EXIT_KEYS = {27, ord("\n"), ord("\r"), curses.KEY_ENTER, ord("q"), ord("Q")}


def run_inspector(rows: list[dict], *, title: str = "Captured packets") -> None:
    """Open the interactive inspector over ``rows`` (needs a real terminal)."""
    if not rows:
        raise ModuleError("No packets captured yet; run 'capture start' first.")
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ModuleError("'inspect' needs an interactive terminal.")
    curses.wrapper(_loop, rows, title)


def _safe_addstr(win, y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
    """Write ``text`` at ``(y, x)`` without ever tripping curses.

    curses raises if a write reaches the bottom-right cell (the cursor would
    advance off-screen). We clamp the length to the space available on the row
    and leave the final cell of the last row untouched, swallowing the harmless
    error if it still occurs.
    """
    height, width = win.getmaxyx()
    if not (0 <= y < height) or x >= width:
        return
    max_len = width - x
    if y == height - 1:  # never touch the very last cell of the screen
        max_len -= 1
    if max_len <= 0:
        return
    try:
        win.addnstr(y, x, text, max_len, attr)
    except curses.error:
        pass


def _fit(text: str, width: int) -> str:
    text = str(text)
    if len(text) <= width:
        return text.ljust(width)
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "\u2026"


def _layout(total_width: int) -> list[tuple[str, str, int]]:
    """Scale column widths to the terminal, giving slack to src/dst."""
    fixed = sum(w for key, _, w in _COLUMNS if key in ("timestamp", "interface", "layer"))
    flexible = max(20, total_width - fixed - len(_COLUMNS))
    per_flex = max(10, flexible // 2)
    layout = []
    for key, label, width in _COLUMNS:
        layout.append((key, label, per_flex if key in ("source", "destination") else width))
    return layout


def _loop(stdscr, rows: list[dict], title: str) -> None:
    try:
        curses.curs_set(0)
    except curses.error:  # some terminals don't support hiding the cursor
        pass
    stdscr.keypad(True)
    selected = 0
    top = 0

    while True:
        height, width = stdscr.getmaxyx()
        layout = _layout(width)
        body_height = max(1, height - 3)

        if selected < top:
            top = selected
        elif selected >= top + body_height:
            top = selected - body_height + 1

        stdscr.erase()
        header = f" {title} - {len(rows)} packet(s)  [Up/Down PgUp/PgDn  Esc/Enter/q]"
        _safe_addstr(stdscr, 0, 0, header.ljust(width), curses.A_BOLD)

        column_line = " ".join(_fit(label, w) for _, label, w in layout)
        _safe_addstr(stdscr, 1, 0, column_line.ljust(width), curses.A_UNDERLINE)

        for offset in range(body_height):
            index = top + offset
            if index >= len(rows):
                break
            row = rows[index]
            line = " ".join(_fit(row.get(key, "-"), w) for key, _, w in layout)
            attr = curses.A_REVERSE if index == selected else curses.A_NORMAL
            _safe_addstr(stdscr, 2 + offset, 0, line.ljust(width), attr)

        footer = f" {selected + 1}/{len(rows)}"
        _safe_addstr(stdscr, height - 1, 0, footer.ljust(width), curses.A_DIM)
        stdscr.refresh()

        key = stdscr.getch()
        if key in _EXIT_KEYS:
            break
        if key == curses.KEY_UP:
            selected = max(0, selected - 1)
        elif key == curses.KEY_DOWN:
            selected = min(len(rows) - 1, selected + 1)
        elif key == curses.KEY_PPAGE:
            selected = max(0, selected - body_height)
        elif key == curses.KEY_NPAGE:
            selected = min(len(rows) - 1, selected + body_height)
        elif key == curses.KEY_HOME:
            selected = 0
        elif key == curses.KEY_END:
            selected = len(rows) - 1

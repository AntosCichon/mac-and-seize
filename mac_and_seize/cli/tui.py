"""Shared terminal UI widgets (the CLI front-end's interactive views).

Currently a minimal vi-like, read-only, scrollable table viewer built on stdlib
``curses``, plus :class:`CursesPresenter` - the CLI's implementation of the
:class:`~mac_and_seize.core.presenter.Presenter` port. Any module can render a
scrollable table via ``context.presenter.table(...)`` without importing this
front-end. Navigation:

* Up / Down            move the selection
* PgUp / PgDn          move a screen at a time
* Home / End           jump to first / last
* Esc / Enter / q      leave the viewer

It is purely a viewer - nothing is modified - and it restores the terminal
cleanly on exit (via :func:`curses.wrapper`) so the REPL prompt returns intact.
"""

from __future__ import annotations

import curses
import logging
import sys
import threading
from typing import Callable

from mac_and_seize.core.presenter import Column
from mac_and_seize.core.errors import ModuleError
from mac_and_seize.util.static import COLORS

try:
    import readline
except ImportError:  # pragma: no cover - readline is unavailable on some OSes
    readline = None

_EXIT_KEYS = {27, ord("\n"), ord("\r"), curses.KEY_ENTER, ord("q"), ord("Q")}


class CursesPresenter:
    """CLI presenter: renders interactive views with ``curses``."""

    def __init__(self) -> None:
        # Serialises writes so overlapping background emitters (a task's
        # notify(), a log line from a worker thread) don't interleave their
        # line rewrites. The prompt provider is installed by the REPL
        # (run_interactive) so we can redraw the live prompt; until then we
        # fall back to a plain print.
        self._lock = threading.Lock()
        self._prompt_provider: Callable[[], str] | None = None
        # While a full-screen curses viewer (table()) owns the terminal, an
        # out-of-band write would scribble over it, so emit_line() buffers into
        # `_deferred` and table() flushes it once the viewer closes.
        self._viewer_active = False
        self._deferred: list[str] = []

    def set_prompt_provider(self, provider: Callable[[], str]) -> None:
        """Let the REPL tell us how to redraw the current prompt line."""
        self._prompt_provider = provider

    def table(self, rows: list[dict], columns: list[Column], *, title: str) -> None:
        with self._lock:
            self._viewer_active = True
        try:
            run_table_viewer(rows, columns, title=title)
        finally:
            with self._lock:
                self._viewer_active = False
                deferred, self._deferred = self._deferred, []
            # The viewer has restored the terminal; emit anything that arrived
            # while it was open, before the REPL redraws its next prompt.
            for line in deferred:
                sys.stdout.write(line + "\n")
            if deferred:
                sys.stdout.flush()

    def notify(self, message: str) -> None:
        """Print ``message`` in green *above* the prompt, leaving it intact."""
        self.emit_line(f"{COLORS['green']}{message}{COLORS['reset']}", spaced_fallback=True)

    def emit_line(self, line: str, *, spaced_fallback: bool = False) -> None:
        """Write one already-rendered ``line`` above the prompt, repainting it.

        Called from background worker threads (a task finishing, a log record
        from a scan worker) while the main thread is blocked in ``input()``
        showing the prompt and any partially-typed command. Letting such a
        write land as-is corrupts the prompt line (it looks like injected
        input), so we erase the current line, print ``line``, then repaint the
        prompt and the in-progress buffer. When no interactive prompt is active
        we just print (``spaced_fallback`` adds a leading newline, wanted for
        one-off notices but not for a stream of log lines). See
        modules/README.md §9.
        """
        interactive = (
            readline is not None
            and self._prompt_provider is not None
            and sys.stdout.isatty()
            and sys.stdin.isatty()
        )
        with self._lock:
            if self._viewer_active:
                # A curses viewer owns the screen; hold the line until it closes.
                self._deferred.append(line)
                return
            if not interactive:
                prefix = "\n" if spaced_fallback else ""
                sys.stdout.write(f"{prefix}{line}\n")
                sys.stdout.flush()
                return
            prompt = self._prompt_provider()
            buffer = readline.get_line_buffer()
            # \r -> column 0, \x1b[K -> clear to end of line, then the line, then
            # repaint prompt + the user's partially-typed command.
            sys.stdout.write(f"\r\x1b[K{line}\n{prompt}{buffer}")
            sys.stdout.flush()


class PromptAwareLogHandler(logging.Handler):
    """Console log handler that keeps the interactive prompt intact.

    Installed by the REPL in place of the plain stderr handler for the duration
    of the interactive session. Records emitted from a **background thread**
    (e.g. a running discovery scan) are printed *above* the prompt via the
    presenter; records from the **main thread** are synchronous with the REPL's
    own output (or arrive between commands), so they print normally to stderr.
    That thread check is what stops a mid-command log line from spuriously
    repainting a prompt that isn't currently displayed.
    """

    def __init__(self, presenter: CursesPresenter) -> None:
        super().__init__()
        self._presenter = presenter

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            if threading.current_thread() is threading.main_thread():
                stream = sys.stderr
                stream.write(message + "\n")
                stream.flush()
            else:
                self._presenter.emit_line(message)
        except Exception:  # noqa: BLE001 - logging must never raise into callers
            self.handleError(record)


def run_table_viewer(
    rows: list[dict], columns: list[Column], *, title: str = ""
) -> None:
    """Open the interactive table viewer over ``rows`` (needs a real terminal)."""
    if not rows:
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ModuleError("An interactive table needs an interactive terminal.")
    curses.wrapper(_loop, rows, columns, title)


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
    return text[: width - 1] + "…"


def _layout(columns: list[Column], total_width: int) -> list[tuple[str, str, int]]:
    """Scale column widths to the terminal, sharing slack among flex columns."""
    fixed = sum(c.width for c in columns if not c.flex)
    flex_count = sum(1 for c in columns if c.flex)
    per_flex = 0
    if flex_count:
        flexible = max(20, total_width - fixed - len(columns))
        per_flex = max(10, flexible // flex_count)
    return [(c.key, c.label, per_flex if c.flex else c.width) for c in columns]


def _loop(stdscr, rows: list[dict], columns: list[Column], title: str) -> None:
    try:
        curses.curs_set(0)
    except curses.error:  # some terminals don't support hiding the cursor
        pass
    stdscr.keypad(True)
    selected = 0
    top = 0

    while True:
        height, width = stdscr.getmaxyx()
        layout = _layout(columns, width)
        body_height = max(1, height - 3)

        if selected < top:
            top = selected
        elif selected >= top + body_height:
            top = selected - body_height + 1

        stdscr.erase()
        header = f" {title} - {len(rows)} row(s)  [Up/Down PgUp/PgDn  Esc/Enter/q]"
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

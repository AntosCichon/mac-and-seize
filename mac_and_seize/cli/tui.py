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

from mac_and_seize.core.presenter import BuiltLayer, Column, LayerType
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
        # The *real* terminal stream our out-of-band writes must go to. The REPL
        # sets this when it proxies sys.stdout/sys.stderr (so stray background
        # writes land above the prompt); emit_line() must bypass that proxy and
        # write to the true terminal, or it would feed its own output back into
        # the proxy and recurse. ``None`` means "not proxied - use sys.stdout".
        self._terminal_stream = None

    def set_prompt_provider(self, provider: Callable[[], str]) -> None:
        """Let the REPL tell us how to redraw the current prompt line."""
        self._prompt_provider = provider

    def set_terminal_stream(self, stream) -> None:
        """Point out-of-band writes at the real terminal (see ``_terminal``).

        Called by the REPL with the genuine ``sys.stdout`` right before it swaps
        in a prompt-aware proxy, and with ``None`` on teardown.
        """
        self._terminal_stream = stream

    @property
    def _terminal(self):
        """The stream out-of-band lines are written to (the real terminal)."""
        return self._terminal_stream if self._terminal_stream is not None else sys.stdout

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
                self._terminal.write(line + "\n")
            if deferred:
                self._terminal.flush()

    def build_packet(
        self,
        catalog: list[LayerType],
        initial: list[BuiltLayer],
        *,
        title: str,
    ) -> list[BuiltLayer] | None:
        with self._lock:
            self._viewer_active = True
        try:
            return run_packet_builder(catalog, initial, title=title)
        finally:
            with self._lock:
                self._viewer_active = False
                deferred, self._deferred = self._deferred, []
            # The builder has restored the terminal; emit anything that arrived
            # while it was open, before the REPL redraws its next prompt.
            for line in deferred:
                self._terminal.write(line + "\n")
            if deferred:
                self._terminal.flush()

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
        out = self._terminal
        with self._lock:
            if self._viewer_active:
                # A curses viewer owns the screen; hold the line until it closes.
                self._deferred.append(line)
                return
            if not interactive:
                prefix = "\n" if spaced_fallback else ""
                out.write(f"{prefix}{line}\n")
                out.flush()
                return
            prompt = self._prompt_provider()
            buffer = readline.get_line_buffer()
            # \r -> column 0, \x1b[K -> clear to end of line, then the line, then
            # repaint prompt + the user's partially-typed command.
            out.write(f"\r\x1b[K{line}\n{prompt}{buffer}")
            out.flush()


class PromptAwareStream:
    """A ``sys.stdout``/``sys.stderr`` proxy that keeps stray writes off the prompt.

    The prompt-aware *log* handler only catches records that flow through the
    logging system. Anything that writes to the real stream directly - a stray
    ``print`` from a worker thread, a library that bypasses logging, a traceback
    on a background thread - would still land raw on the prompt line. Installed
    by the REPL for the session, this proxy closes that gap app-wide:

    * writes from the **main thread** pass straight through (the REPL's own
      output, ``input()``'s prompt, rich tables - all untouched);
    * writes from a **background thread** are buffered per thread until a newline
      and then lifted *above* the prompt via the presenter, exactly like an
      out-of-band log line.

    The presenter's own out-of-band writes go to the real stream (see
    :meth:`CursesPresenter.set_terminal_stream`), so routing background writes
    through it here never feeds back into the proxy.
    """

    def __init__(self, real, presenter: "CursesPresenter") -> None:
        self._real = real
        self._presenter = presenter
        self._buffers: dict[int, str] = {}
        self._lock = threading.Lock()

    def write(self, s) -> int:
        if not isinstance(s, str):
            return self._real.write(s)
        if threading.current_thread() is threading.main_thread():
            return self._real.write(s)
        # Background thread: accumulate and emit only complete lines above the
        # prompt, holding any trailing partial line until its newline arrives.
        with self._lock:
            data = self._buffers.get(threading.get_ident(), "") + s
            parts = data.split("\n")
            self._buffers[threading.get_ident()] = parts.pop()
        for line in parts:
            self._presenter.emit_line(line)
        return len(s)

    def flush(self) -> None:
        self._real.flush()

    def isatty(self) -> bool:
        return self._real.isatty()

    def fileno(self) -> int:
        return self._real.fileno()

    def __getattr__(self, name):
        # Delegate everything else (encoding, writable, buffer, ...) to the real
        # stream. Only reached for attributes not defined above.
        return getattr(self._real, name)


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


# --- Interactive packet builder ------------------------------------------------

_ENTER_KEYS = {ord("\n"), ord("\r"), curses.KEY_ENTER}
_BACKSPACE_KEYS = {curses.KEY_BACKSPACE, 127, 8}


def run_packet_builder(
    catalog: list[LayerType], initial: list[BuiltLayer], *, title: str = ""
) -> list[BuiltLayer] | None:
    """Open the interactive packet builder (needs a real terminal).

    Returns the ordered layers the user assembled, or ``None`` if they
    cancelled. See :class:`_PacketBuilder` for the navigation.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ModuleError("The interactive packet builder needs an interactive terminal.")
    return curses.wrapper(
        lambda stdscr: _PacketBuilder(stdscr, catalog, initial, title).run()
    )


class _PacketBuilder:
    """A small vi-like curses form for stacking and editing packet layers.

    Three nested views over a mutable list of :class:`BuiltLayer`:

    * **layer list** - ``Up/Down`` select, ``a`` add a layer (opens the catalog
      picker), ``d`` delete, ``[`` / ``]`` reorder, ``Enter`` edit the selected
      layer's fields, ``s`` save (return the layers), ``Esc`` / ``q`` cancel.
    * **catalog picker** - choose a layer type to append.
    * **field editor** - per-field values, each edited on a single input line.

    It mutates only its own copy of the layers and returns plain
    :class:`BuiltLayer` data; the module turns that into a packet.
    """

    def __init__(self, stdscr, catalog: list[LayerType], initial: list[BuiltLayer], title: str) -> None:
        self.stdscr = stdscr
        self.catalog = catalog
        self.by_name = {layer.name: layer for layer in catalog}
        # Own copy so a cancel leaves the caller's `initial` untouched.
        self.layers = [BuiltLayer(bl.name, dict(bl.values)) for bl in initial]
        self.title = title or "Packet builder"
        self.selected = 0

    def run(self) -> list[BuiltLayer] | None:
        try:
            curses.curs_set(0)
        except curses.error:  # some terminals don't support hiding the cursor
            pass
        self.stdscr.keypad(True)
        while True:
            self._draw_layers()
            key = self.stdscr.getch()
            if key in (27, ord("q"), ord("Q")):
                return None
            if key in (ord("s"), ord("S")):
                return self.layers
            if key in (ord("a"), ord("A")):
                chosen = self._pick_layer()
                if chosen is not None:
                    self.layers.append(
                        BuiltLayer(chosen.name, {f.key: f.default for f in chosen.fields})
                    )
                    self.selected = len(self.layers) - 1
                continue
            if not self.layers:
                continue
            if key in (ord("d"), ord("D")):
                del self.layers[self.selected]
                self.selected = max(0, min(self.selected, len(self.layers) - 1))
            elif key in _ENTER_KEYS:
                self._edit_layer(self.layers[self.selected])
            elif key == ord("[") and self.selected > 0:
                self.layers[self.selected - 1], self.layers[self.selected] = (
                    self.layers[self.selected], self.layers[self.selected - 1]
                )
                self.selected -= 1
            elif key == ord("]") and self.selected < len(self.layers) - 1:
                self.layers[self.selected + 1], self.layers[self.selected] = (
                    self.layers[self.selected], self.layers[self.selected + 1]
                )
                self.selected += 1
            elif key == curses.KEY_UP:
                self.selected = max(0, self.selected - 1)
            elif key == curses.KEY_DOWN:
                self.selected = min(len(self.layers) - 1, self.selected + 1)

    def _draw_layers(self) -> None:
        stdscr = self.stdscr
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        header = f" {self.title}"
        _safe_addstr(stdscr, 0, 0, header.ljust(width), curses.A_BOLD)
        keys = " a:add  d:delete  Enter:edit  [ ]:reorder  s:save  Esc/q:cancel"
        _safe_addstr(stdscr, 1, 0, keys.ljust(width), curses.A_UNDERLINE)
        if not self.layers:
            _safe_addstr(stdscr, 3, 0, "(no layers yet - press 'a' to add one)", curses.A_DIM)
        for index, layer in enumerate(self.layers):
            attr = curses.A_REVERSE if index == self.selected else curses.A_NORMAL
            text = f" {index + 1}. {self._summary(layer)}"
            _safe_addstr(stdscr, 3 + index, 0, _fit(text, width).ljust(width), attr)
        footer = " 's' saves so you can name it; nothing is sent from here."
        _safe_addstr(stdscr, height - 1, 0, footer.ljust(width), curses.A_DIM)
        stdscr.refresh()

    @staticmethod
    def _summary(layer: BuiltLayer) -> str:
        set_values = [f"{key}={value}" for key, value in layer.values.items() if value != ""]
        return f"{layer.name}  {', '.join(set_values)}" if set_values else layer.name

    def _pick_layer(self) -> LayerType | None:
        stdscr = self.stdscr
        selected = 0
        while True:
            height, width = stdscr.getmaxyx()
            stdscr.erase()
            _safe_addstr(
                stdscr, 0, 0,
                " Add layer  [Up/Down  Enter:add  Esc:cancel]".ljust(width),
                curses.A_BOLD,
            )
            for index, layer_type in enumerate(self.catalog):
                attr = curses.A_REVERSE if index == selected else curses.A_NORMAL
                _safe_addstr(stdscr, 2 + index, 0, _fit(f" {layer_type.name}", width).ljust(width), attr)
            stdscr.refresh()
            key = stdscr.getch()
            if key == 27:
                return None
            if key in _ENTER_KEYS:
                return self.catalog[selected]
            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(self.catalog) - 1, selected + 1)

    def _edit_layer(self, layer: BuiltLayer) -> None:
        stdscr = self.stdscr
        layer_type = self.by_name.get(layer.name)
        if layer_type is None or not layer_type.fields:
            return
        fields = layer_type.fields
        selected = 0
        while True:
            height, width = stdscr.getmaxyx()
            stdscr.erase()
            _safe_addstr(
                stdscr, 0, 0,
                f" {layer.name} fields  [Up/Down  Enter:edit  Esc:back]".ljust(width),
                curses.A_BOLD,
            )
            for index, field in enumerate(fields):
                value = layer.values.get(field.key, "")
                shown = value if value != "" else "(default)"
                attr = curses.A_REVERSE if index == selected else curses.A_NORMAL
                line = f" {field.label:<18} {shown}"
                _safe_addstr(stdscr, 2 + index, 0, _fit(line, width).ljust(width), attr)
            _safe_addstr(stdscr, height - 1, 0, _fit(f" {fields[selected].help}", width).ljust(width), curses.A_DIM)
            stdscr.refresh()
            key = stdscr.getch()
            if key == 27:
                return
            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(fields) - 1, selected + 1)
            elif key in _ENTER_KEYS:
                field = fields[selected]
                result = self._prompt_text(
                    f"{layer.name}.{field.key}",
                    field.help,
                    layer.values.get(field.key, ""),
                )
                if result is not None:
                    layer.values[field.key] = result

    def _prompt_text(self, label: str, hint: str, initial: str) -> str | None:
        """Edit a single value on one line; Enter commits, Esc keeps the old one."""
        stdscr = self.stdscr
        buffer = list(initial)
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        try:
            while True:
                height, width = stdscr.getmaxyx()
                stdscr.erase()
                _safe_addstr(stdscr, 0, 0, f" Edit {label}".ljust(width), curses.A_BOLD)
                if hint:
                    _safe_addstr(stdscr, 1, 0, _fit(f" {hint}", width).ljust(width), curses.A_DIM)
                _safe_addstr(stdscr, 3, 0, "Enter=confirm  Esc=cancel  Backspace=delete", curses.A_DIM)
                text = "".join(buffer)
                _safe_addstr(stdscr, 5, 0, "> " + text)
                stdscr.move(5, min(2 + len(text), width - 1))
                stdscr.refresh()
                key = stdscr.getch()
                if key == 27:
                    return None
                if key in _ENTER_KEYS:
                    return "".join(buffer)
                if key in _BACKSPACE_KEYS:
                    if buffer:
                        buffer.pop()
                elif 32 <= key <= 126:
                    buffer.append(chr(key))
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass

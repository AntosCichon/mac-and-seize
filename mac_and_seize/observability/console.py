"""A colorized console formatter, ported from the old ``TerminalMessage``."""

from __future__ import annotations

import logging

from mac_and_seize.util.static import COLORS, LEVEL_COLORS


class ColorFormatter(logging.Formatter):
    """Formatter that colorizes the level name using ANSI escapes.

    Colors are disabled automatically when the stream is not a TTY (handled by
    the handler via :meth:`should_color`), keeping piped/redirected output
    clean.
    """

    def __init__(self, *args, use_color: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if not self.use_color:
            return message
        color = COLORS.get(LEVEL_COLORS.get(record.levelname, ""), "")
        if not color:
            return message
        return f"{color}{message}{COLORS['reset']}"

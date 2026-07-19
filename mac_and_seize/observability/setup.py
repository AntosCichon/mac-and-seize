"""Configure stdlib logging for the application.

Replaces the previous bespoke ``LogMessage`` / ``TerminalMessage`` system.
Modules simply do ``logging.getLogger(__name__)`` (or
``mac_and_seize.observability.get_logger(__name__)``) and emit records; this
module wires up where those records go:

- a colorized console handler (stderr, only colored on a TTY),
- a file handler under ``logging.directory / logging.filename``,
- an ``atexit`` hook that zips the log directory (and optionally removes the
  originals) via :func:`mac_and_seize.util.export.export_logs`.
"""

from __future__ import annotations

import atexit
import logging
import sys
import warnings
from pathlib import Path

from mac_and_seize.config import AppConfig
from mac_and_seize.observability.console import ColorFormatter
from mac_and_seize.util.export import export_logs

LOGGER_NAME = "mac_and_seize"

_configured = False


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger under the application's namespace."""
    return logging.getLogger(name if name else LOGGER_NAME)


def configure_logging(config: AppConfig) -> logging.Logger:
    """Idempotently configure and return the application's root logger."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    if _configured:
        return logger

    level = logging.getLevelNamesMapping().get(config.logging.level, logging.INFO)
    logger.setLevel(level)
    logger.propagate = False

    # The console handler streams records to the live session. It is opt-in
    # (logging.terminal): when disabled, records go to the file only and the
    # interactive prompt stays quiet (the front-end finds no "console" handler
    # to swap, so nothing is printed above the prompt either).
    if config.logging.terminal:
        console = logging.StreamHandler(stream=sys.stderr)
        console.set_name("console")  # so the interactive front-end can find/replace it
        console.setFormatter(
            ColorFormatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
                use_color=sys.stderr.isatty(),
            )
        )
        logger.addHandler(console)

    log_dir = Path(config.logging.directory)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / config.logging.filename
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] "
            "[%(filename)s:%(lineno)d] %(message)s"
        )
    )
    logger.addHandler(file_handler)

    _route_warnings_through(logger)

    atexit.register(_shutdown, config)
    _configured = True
    logger.debug(
        "Logging configured (level=%s, file=%s)", config.logging.level, log_path
    )
    return logger


def _route_warnings_through(logger: logging.Logger) -> None:
    """Send Python ``warnings.warn(...)`` output through the app logger.

    Third-party libraries (scapy most of all) raise ``warnings.warn`` notices
    that the ``warnings`` module prints straight to stderr, outside our
    handlers. During an interactive session that lands raw on the prompt line
    and corrupts it - the same failure mode as a stray ``print`` from a worker
    thread (see ``modules/README.md`` §9). Routing them through a child of the
    app logger makes them flow through whatever handler is installed (including
    the prompt-aware handler the REPL swaps in, which lifts a background-thread
    record *above* the prompt) and be formatted like our own records instead of
    a bare library traceback line.

    We only forward warnings the ``warnings`` filters would have shown anyway,
    so this reroutes noise rather than amplifying it.
    """
    warnings_log = logger.getChild("warnings")

    def _show(message, category, filename, lineno, file=None, line=None) -> None:
        warnings_log.warning("%s: %s (%s:%s)", category.__name__, message, filename, lineno)

    warnings.showwarning = _show


def _shutdown(config: AppConfig) -> None:
    """Flush/close handlers then archive the log directory."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        try:
            handler.flush()
            handler.close()
        except Exception:  # noqa: BLE001 - best-effort on interpreter shutdown
            pass
        logger.removeHandler(handler)

    export_logs(
        config.logging.directory,
        config.setup.export_directory,
        remove_original=config.logging.remove_on_exit,
    )

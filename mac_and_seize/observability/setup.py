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

    console = logging.StreamHandler(stream=sys.stderr)
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

    atexit.register(_shutdown, config)
    _configured = True
    logger.debug(
        "Logging configured (level=%s, file=%s)", config.logging.level, log_path
    )
    return logger


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

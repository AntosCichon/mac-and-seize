"""Logging / observability setup for the application.

Named ``observability`` rather than ``logging`` to avoid shadowing the stdlib
``logging`` module inside the package.
"""

from mac_and_seize.observability.setup import (
    LOGGER_NAME,
    configure_logging,
    get_logger,
)

__all__ = ["LOGGER_NAME", "configure_logging", "get_logger"]

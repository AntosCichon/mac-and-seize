"""Placeholder application factory for the future web interface.

The signature (``create_app(context)``) is the seam a real implementation will
fill in: take an already-built :class:`~mac_and_seize.core.context.AppContext`
and return a configured web application (e.g. FastAPI or Flask) whose routes
enumerate ``context.actions`` and/or call module services via
``context.service("<key>")``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext


class ServerNotImplementedError(NotImplementedError):
    """Raised until the web interface is implemented."""


def create_app(context: "AppContext"):
    raise ServerNotImplementedError(
        "The web interface is not implemented yet. The action registry "
        "(context.actions) and module services (context.service('<key>')) are "
        "ready to be wired to HTTP routes; see mac_and_seize/server/README.md."
    )

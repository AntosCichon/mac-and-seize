"""Shared error types recognised by every front-end.

Modules raise these so that the CLI (and the future web interface) can show a
clean message instead of a traceback. Keep this module dependency-free: it is
imported by both the framework and every feature module.
"""

from __future__ import annotations


class ModuleError(RuntimeError):
    """Base class for *expected*, user-facing failures raised by a module.

    Raise this (or a subclass) for predictable operational failures - a device
    that is missing, an external command that failed, hardware that is in the
    wrong state, and so on. Front-ends catch :class:`ModuleError` and render its
    message without a stack trace.

    For *bad user input* raise the built-in :class:`ValueError` instead; the
    front-ends treat it the same way (clean message, session stays alive).
    """

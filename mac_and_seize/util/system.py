"""System-level helpers."""

import os
import sys


def is_root() -> bool:
    return os.geteuid() == 0


def relaunch_as_root() -> None:
    """Replace the current process with a ``sudo``-elevated copy.

    Uses :func:`os.execvp`, so on success this does **not** return - the current
    process image is replaced. ``sys.argv`` and the working directory are
    preserved, so the app restarts in the same mode. No-op when already root.
    """
    if is_root():
        return
    os.execvp("sudo", ["sudo", sys.executable, *sys.argv])


def require_root() -> None:
    """Re-exec the process under ``sudo`` when not already running as root."""
    if is_root():
        return
    print(
        "This tool requires root privileges. "
        "Enter password to continue or press Ctrl+C to exit."
    )
    relaunch_as_root()

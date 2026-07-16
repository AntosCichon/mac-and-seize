"""Shared plumbing for privileged system commands.

Every adapter that shells out to a system tool (``ip``, ``ethtool``, ...) runs
it through :func:`run` so command execution, error surfacing, and shell-injection
avoidance live in exactly one place. Commands are always passed as an argument
list (never a shell string).

``PrivilegedCommandError`` subclasses the shared :class:`ModuleError` so the
front-ends render it as a clean message rather than a traceback.
"""

from __future__ import annotations

import subprocess

from mac_and_seize.core.errors import ModuleError


class PrivilegedCommandError(ModuleError):
    """Raised when a privileged command fails or is unavailable."""


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run ``cmd`` (an argument list), returning the completed process.

    Raises :class:`PrivilegedCommandError` if the binary is missing or the
    command exits non-zero, with the tool's stderr as the message.
    """
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise PrivilegedCommandError(
            f"Command not found: {cmd[0]!r}. Is it installed and on PATH?"
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() or f"exit code {exc.returncode}"
        raise PrivilegedCommandError(
            f"Command {' '.join(cmd)!r} failed: {detail}"
        ) from exc


def family_flag(version: int) -> str:
    """Map an IP version (4/6) to the ``ip`` family flag (``-4``/``-6``)."""
    if version not in (4, 6):
        raise ValueError(f"Invalid IP version {version!r}; expected 4 or 6.")
    return "-4" if version == 4 else "-6"

"""Small, dependency-free formatting helpers shared across the app."""

from __future__ import annotations


def format_hms(seconds: float) -> str:
    """Render a duration in seconds as ``HH:MM:SS``."""
    total = int(seconds)
    return f"{total // 3600:02d}:{(total % 3600) // 60:02d}:{total % 60:02d}"

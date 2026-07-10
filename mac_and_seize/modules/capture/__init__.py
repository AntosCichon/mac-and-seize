"""Capture module: sniff and record packets.

Auto-discovered via :func:`register`. Registers one service (``"capture"``) and
the top-level ``capture`` command.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.capture.actions import SERVICE, build_actions
from mac_and_seize.modules.capture.service import CaptureService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="capture",
        services={SERVICE: CaptureService},
        actions=build_actions(),
        order=20,
    )

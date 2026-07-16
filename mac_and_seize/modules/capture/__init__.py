"""Capture module: background packet capture, filtering and inspection.

Auto-discovered via :func:`register`. Registers one session-scoped service
(``"capture"``) and the ``capture`` command group (start/stop/export/clear/
summary/inspect plus a ``filter`` subgroup).
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.capture.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.capture.service import CaptureService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="capture",
        services={SERVICE: CaptureService},
        actions=build_actions(),
        group_descriptions=GROUP_DESCRIPTIONS,
        order=20,
    )

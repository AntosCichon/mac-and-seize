"""Capture module: background packet capture, filtering and inspection.

Auto-discovered via :func:`register`. Registers two session-scoped services -
``"capture"`` (wired) and ``"capture_wireless"`` (802.11 monitor mode) - and the
``capture`` command group: start/stop/export/import/clear/summary/inspect plus a
``filter`` subgroup, and a ``wireless`` subgroup for monitor-mode 802.11 capture.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.capture.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.capture.service import CaptureService
from mac_and_seize.modules.capture.wireless_actions import (
    WIRELESS_GROUP_DESCRIPTIONS,
    WIRELESS_SERVICE,
    build_wireless_actions,
)
from mac_and_seize.modules.capture.wireless_service import WirelessCaptureService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="capture",
        services={
            SERVICE: CaptureService,
            WIRELESS_SERVICE: WirelessCaptureService,
        },
        actions=build_actions() + build_wireless_actions(),
        group_descriptions={**GROUP_DESCRIPTIONS, **WIRELESS_GROUP_DESCRIPTIONS},
        order=20,
    )

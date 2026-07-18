"""Wireless module: 802.11 (Wi-Fi) monitor-mode capture.

Auto-discovered via :func:`register`. Registers one session-scoped service -
``"wireless_capture"`` (background monitor-mode frame capture with channel
sweeping and an activity scan) - and the top-level ``wireless`` command group.
Entering monitor mode is done quietly inside ``capture start`` and undone on
``stop``, so there is no separate monitor/mode/channel command surface. It is a
peer of the wired :mod:`mac_and_seize.modules.capture` module; both build on the
shared :class:`~mac_and_seize.net.session.PacketSession` base in ``net/``.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.wireless.actions import (
    WIRELESS_CAPTURE_SERVICE,
    WIRELESS_GROUP_DESCRIPTIONS,
    build_wireless_actions,
)
from mac_and_seize.modules.wireless.capture import WirelessCaptureService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="wireless",
        services={WIRELESS_CAPTURE_SERVICE: WirelessCaptureService},
        actions=build_wireless_actions(),
        group_descriptions=WIRELESS_GROUP_DESCRIPTIONS,
        order=25,
    )

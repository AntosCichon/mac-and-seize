"""Wireless module: 802.11 (Wi-Fi) monitor-mode toolkit.

Auto-discovered via :func:`register`. Registers two session-scoped services -
``"wireless_capture"`` (background monitor-mode frame capture with channel
sweeping and an activity scan) and ``"wireless_beacon"`` (background beacon-flood
"spam" jobs) - plus the top-level ``wireless`` command group. Both share the
monitor-mode radio lifecycle in
:class:`~mac_and_seize.modules.wireless.radio.MonitorRadioMixin`: entering monitor
mode is done quietly when work starts and undone when it stops, so there is no
separate monitor/mode/channel command surface. The module is a peer of the wired
:mod:`mac_and_seize.modules.capture` module; capture builds on the shared
:class:`~mac_and_seize.net.session.PacketSession` base in ``net/``.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.wireless.actions import (
    WIRELESS_BEACON_SERVICE,
    WIRELESS_CAPTURE_SERVICE,
    WIRELESS_GROUP_DESCRIPTIONS,
    build_wireless_actions,
)
from mac_and_seize.modules.wireless.beacon import BeaconService
from mac_and_seize.modules.wireless.capture import WirelessCaptureService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="wireless",
        services={
            WIRELESS_CAPTURE_SERVICE: WirelessCaptureService,
            WIRELESS_BEACON_SERVICE: BeaconService,
        },
        actions=build_wireless_actions(),
        group_descriptions=WIRELESS_GROUP_DESCRIPTIONS,
        order=25,
    )

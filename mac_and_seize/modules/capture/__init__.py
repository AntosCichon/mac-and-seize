"""Capture module: background (wired) packet capture, filtering and inspection.

Auto-discovered via :func:`register`. Registers the session-scoped ``"capture"``
service and the ``capture`` command group: start/stop/export/import/clear/
summary/inspect plus a ``filter`` subgroup. 802.11 monitor-mode capture lives in
its own peer :mod:`mac_and_seize.modules.wireless` module; both build on the
shared :class:`~mac_and_seize.net.session.PacketSession` base in ``net/``.
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

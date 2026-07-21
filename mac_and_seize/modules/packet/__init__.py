"""Packet module: craft, store, send and import/export named packets.

Auto-discovered via :func:`register`. Registers the session-scoped ``"packet"``
service and the ``packet`` command group: ``craft`` and a ``presets`` subgroup
open an interactive builder (via the front-end ``Presenter``); ``list``,
``send`` and ``export``/``import`` manage and use the saved packets. Packets are
built from the shared :class:`~mac_and_seize.net.Packet` type and sent through
the shared scapy adapter.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.packet.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.packet.service import PacketService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="packet",
        services={SERVICE: PacketService},
        actions=build_actions(),
        group_descriptions=GROUP_DESCRIPTIONS,
        order=30,
    )

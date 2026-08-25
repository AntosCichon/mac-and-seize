"""ARP-layer automations: ARP cache poisoning via forged ARP replies.

Exposes the ``lan arp`` command surface (``spoof`` / ``stop``) and the
session-scoped :class:`~mac_and_seize.modules.lan.arp.service.ArpSpoofService`.
The parent :mod:`mac_and_seize.modules.lan` package aggregates the names below
into the module's :class:`~mac_and_seize.core.plugins.ModuleSpec`.
"""

from __future__ import annotations

from mac_and_seize.modules.lan.arp.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.lan.arp.service import ArpSpoofService

#: Service key -> factory, merged into the module's services by ``lan.register()``.
SERVICES = {SERVICE: ArpSpoofService}

__all__ = [
    "GROUP_DESCRIPTIONS",
    "SERVICE",
    "SERVICES",
    "ArpSpoofService",
    "build_actions",
]

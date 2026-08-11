"""ARP-layer automations: ARP cache poisoning via forged ARP replies.

Exposes the ``l2 arp`` command surface (``spoof`` / ``stop``) and the
session-scoped :class:`~mac_and_seize.modules.l2.arp.service.ArpSpoofService`.
The parent :mod:`mac_and_seize.modules.l2` package aggregates the names below
into the module's :class:`~mac_and_seize.core.plugins.ModuleSpec`.
"""

from __future__ import annotations

from mac_and_seize.modules.l2.arp.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.l2.arp.service import ArpSpoofService

#: Service key -> factory, merged into the module's services by ``l2.register()``.
SERVICES = {SERVICE: ArpSpoofService}

__all__ = [
    "GROUP_DESCRIPTIONS",
    "SERVICE",
    "SERVICES",
    "ArpSpoofService",
    "build_actions",
]

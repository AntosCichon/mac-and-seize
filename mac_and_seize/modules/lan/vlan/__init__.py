"""VLAN automations: DTP spoofing and 802.1Q double-tag hopping.

Exposes the ``lan vlan`` command surface (``learn`` / ``dtp-spoof`` / ``hop`` /
``stop``) and the session-scoped
:class:`~mac_and_seize.modules.lan.vlan.service.VlanService`. The parent
:mod:`mac_and_seize.modules.lan` package aggregates the names below into the
module's :class:`~mac_and_seize.core.plugins.ModuleSpec`.
"""

from __future__ import annotations

from mac_and_seize.modules.lan.vlan.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.lan.vlan.service import VlanService

#: Service key -> factory, merged into the module's services by ``lan.register()``.
SERVICES = {SERVICE: VlanService}

__all__ = [
    "GROUP_DESCRIPTIONS",
    "SERVICE",
    "SERVICES",
    "VlanService",
    "build_actions",
]

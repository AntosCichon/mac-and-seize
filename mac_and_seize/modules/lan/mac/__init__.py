"""MAC-layer automations: CAM/MAC-table saturation traffic generation.

Exposes the ``lan mac`` command surface (``flood`` / ``stop``) and the
session-scoped :class:`~mac_and_seize.modules.lan.mac.service.MacFloodService`.
The parent :mod:`mac_and_seize.modules.lan` package aggregates the names below
into the module's :class:`~mac_and_seize.core.plugins.ModuleSpec`.
"""

from __future__ import annotations

from mac_and_seize.modules.lan.mac.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.lan.mac.service import MacFloodService

#: Service key -> factory, merged into the module's services by ``lan.register()``.
SERVICES = {SERVICE: MacFloodService}

__all__ = [
    "GROUP_DESCRIPTIONS",
    "SERVICE",
    "SERVICES",
    "MacFloodService",
    "build_actions",
]

"""STP automations: root-bridge spoofing, BPDU flooding, and passive learn.

Exposes the ``lan stp`` command surface (``learn`` / ``spoof`` / ``dos`` /
``stop``) and the session-scoped
:class:`~mac_and_seize.modules.lan.stp.service.StpService`. The parent
:mod:`mac_and_seize.modules.lan` package aggregates the names below into the
module's :class:`~mac_and_seize.core.plugins.ModuleSpec`.
"""

from __future__ import annotations
from mac_and_seize.modules.lan.stp.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.lan.stp.service import StpService

#: Service key -> factory, merged into the module's services by ``lan.register()``.
SERVICES = {SERVICE: StpService}
__all__ = [
    "GROUP_DESCRIPTIONS",
    "SERVICE",
    "SERVICES",
    "StpService",
    "build_actions",
]

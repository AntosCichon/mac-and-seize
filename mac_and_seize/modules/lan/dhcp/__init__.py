"""DHCP automations: address-pool starvation and a rogue DHCP server.

Exposes the ``lan dhcp`` command surface (``find``, the ``starve`` group and the
``server`` group) and the session-scoped
:class:`~mac_and_seize.modules.lan.dhcp.service.DhcpService`. The parent
:mod:`mac_and_seize.modules.lan` package aggregates the names below into the
module's :class:`~mac_and_seize.core.plugins.ModuleSpec`.

The area is split three ways: :mod:`protocol` builds and parses frames and knows
nothing else, :mod:`pool` holds the records for one segment's addresses, and
:mod:`service` owns the threads, the sockets and the lifecycle.
"""

from __future__ import annotations

from mac_and_seize.modules.lan.dhcp.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.lan.dhcp.service import DhcpService

#: Service key -> factory, merged into the module's services by ``lan.register()``.
SERVICES = {SERVICE: DhcpService}

__all__ = [
    "GROUP_DESCRIPTIONS",
    "SERVICE",
    "SERVICES",
    "DhcpService",
    "build_actions",
]

"""Discovery module: find live hosts on the network.

Auto-discovered via :func:`register`. Registers one session-scoped service
(``"discovery"``) and the ``discovery`` command group: ``host``
(scan/cancel/import/list/clear/summary - scapy ARP/ICMP sweeps, plus identifying
active hosts from an imported pcap) and a ``service`` stub for future
port/service discovery.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.discovery.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.discovery.service import DiscoveryService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="discovery",
        services={SERVICE: DiscoveryService},
        actions=build_actions(),
        group_descriptions=GROUP_DESCRIPTIONS,
        order=40,
    )

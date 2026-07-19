"""Discovery module: find live hosts and their open ports on the network.

Auto-discovered via :func:`register`. Registers one session-scoped service
(``"discovery"``) that keeps a single, host-oriented store, and the flat
``discovery`` command group: ``scan`` (scapy ARP host sweep), ``tcp``/``udp``
(background TCP SYN / UDP port scans that attach open ports to their host, with a
``discovered`` target that scans every host found so far), ``import`` (identify
active hosts from a pcap), ``inspect`` (interactive host/ports table), and
``list``/``clear``/``summary``/``cancel``.
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

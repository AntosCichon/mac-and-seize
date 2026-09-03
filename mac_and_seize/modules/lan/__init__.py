"""LAN module: LAN (link-layer and above) network automations for authorized testing.

Auto-discovered via :func:`register`. Unlike a flat feature module, ``lan`` is an
umbrella over several LAN areas, each in its own sub-package: ``mac`` (CAM/
MAC-table saturation - the ``flood`` / ``stop`` commands), ``arp`` (ARP cache
poisoning - the ``spoof`` / ``stop`` commands, plus ``--relay`` on ``spoof`` for
an on-segment L2 MiTM), ``stp`` (spanning-tree reconnaissance and BPDU
injection - ``learn`` / ``spoof`` / ``dos`` / ``stop``, plus ``--relay
<egress-iface>`` on ``spoof`` for a two-NIC straddle bridge), ``dhcp`` (pool
starvation and rogue server - ``find`` / ``starve`` / ``server``, plus
mutually-exclusive ``--relay`` / ``--nat-relay`` on ``server start`` for
one-way scapy vs. two-way kernel-NAT MiTM), and ``vlan`` (DTP spoofing and
802.1Q double-tag hopping - ``learn`` / ``dtp-spoof`` / ``hop`` / ``stop``,
with ``--mode {desirable,trunk}`` on ``dtp-spoof`` picking which DTP status
the hellos advertise). ``register()`` aggregates each area's services, actions and
group descriptions into one :class:`~mac_and_seize.core.plugins.ModuleSpec`, so
implementing an area later is just filling in its sub-package - it is already
listed here.

The ``--relay`` / ``--nat-relay`` extensions delegate to the shared
:mod:`~mac_and_seize.modules.relay` module through
``context.service("relay")``; see ``modules/README.md`` §8 for the coupling
pattern and the plan at ``.cursor/plans/`` for the full design.

Sub-packages are *internal*: module discovery only scans the direct children of
``mac_and_seize.modules`` (see :mod:`mac_and_seize.core.plugins`), so ``lan.mac``
and friends never register on their own; this file is what wires them together.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.lan import arp, dhcp, mac, stp, vlan

#: The area sub-packages, in display order. Each exposes ``SERVICES`` (service
#: key -> zero-arg factory), ``GROUP_DESCRIPTIONS`` and ``build_actions()``.
_AREAS = (mac, arp, stp, dhcp, vlan)


def register() -> ModuleSpec:
    services: dict = {}
    actions: list = []
    group_descriptions: dict = {
        "lan": "LAN automations (link-layer and above)",
    }
    for area in _AREAS:
        services.update(getattr(area, "SERVICES", {}))
        actions.extend(area.build_actions())
        group_descriptions.update(getattr(area, "GROUP_DESCRIPTIONS", {}))
    return ModuleSpec(
        name="lan",
        services=services,
        actions=actions,
        group_descriptions=group_descriptions,
        order=50,
    )

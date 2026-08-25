"""LAN module: LAN (link-layer and above) network automations for authorized testing.

Auto-discovered via :func:`register`. Unlike a flat feature module, ``lan`` is an
umbrella over several LAN areas, each in its own sub-package: ``mac`` (CAM/
MAC-table saturation - the ``flood`` / ``stop`` commands), ``arp`` (ARP cache
poisoning - the ``spoof`` / ``stop`` commands) plus ``dhcp`` and ``vlan``
skeletons that will grow their own commands later. ``register()`` aggregates
each area's services, actions and group descriptions into one
:class:`~mac_and_seize.core.plugins.ModuleSpec`, so implementing an area later is
just filling in its sub-package - it is already listed here.

Sub-packages are *internal*: module discovery only scans the direct children of
``mac_and_seize.modules`` (see :mod:`mac_and_seize.core.plugins`), so ``lan.mac``
and friends never register on their own; this file is what wires them together.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.lan import arp, dhcp, mac, vlan

#: The area sub-packages, in display order. Each exposes ``SERVICES`` (service
#: key -> zero-arg factory), ``GROUP_DESCRIPTIONS`` and ``build_actions()``.
_AREAS = (mac, arp, dhcp, vlan)


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

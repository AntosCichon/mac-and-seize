"""Interface module: inspect and control network interfaces.

Auto-discovered via :func:`register`. Registers one service (``"interface"``)
and the interface command tree (list/show/state/mac/ip4/ip6).
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.interface.actions import GROUP_DESCRIPTIONS, SERVICE, build_actions
from mac_and_seize.modules.interface.service import InterfaceService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="interface",
        services={SERVICE: InterfaceService},
        actions=build_actions(),
        group_descriptions=GROUP_DESCRIPTIONS,
        order=10,
    )

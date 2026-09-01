"""Relay module: centralized MiTM/forwarding service.

Turns the tool's existing redirection primitives (:mod:`lan.arp`,
:mod:`lan.dhcp`, :mod:`lan.stp`) into real MiTMs by pairing their poisoning
with a receive-and-reinject pipeline (or, for the rogue-DHCP two-way case,
kernel forwarding + nftables NAT).

Session-scoped :class:`~mac_and_seize.modules.relay.service.RelayService` owns
the registry of running flows; attack modules acquire relay handles via
``context.service("relay").begin_*(...)`` when their ``--relay`` /
``--nat-relay`` flag is set. The user surface here is intentionally small:
``relay list`` for a view, ``relay stop`` for a global tear-down. Flows are
started through the attack modules per the plan's coupling choice.

See ``.cursor/plans/relay_module_design_*.plan.md`` for the design and
tradeoffs, and ``mac_and_seize/net/relay.py`` /
``mac_and_seize/net/adapters/forwarding.py`` for the shared plumbing this
module orchestrates.
"""

from __future__ import annotations

from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.relay.actions import (
    GROUP_DESCRIPTIONS,
    SERVICE,
    build_actions,
)
from mac_and_seize.modules.relay.service import RelayService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="relay",
        services={SERVICE: RelayService},
        actions=build_actions(),
        group_descriptions=GROUP_DESCRIPTIONS,
        order=55,
    )

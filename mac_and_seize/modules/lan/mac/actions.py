"""Actions for the ``lan mac`` command group (CAM/MAC-table saturation).

Two commands, both root-only: ``flood`` starts a background job that injects
frames with a per-packet randomized source MAC on an interface, and ``stop`` ends
the flood running on an interface. Handlers stay thin - they translate parsed
values into calls on the session-scoped
:class:`~mac_and_seize.modules.lan.mac.service.MacFloodService`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.lan.mac.service import MacFloodService

SERVICE = "lan_mac"

GROUP_DESCRIPTIONS = {
    "lan.mac": "MAC-layer automations (CAM/MAC-table saturation)",
}


def _service(context: "AppContext") -> "MacFloodService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _flood(context: "AppContext", values: dict) -> str:
    return _service(context).flood(
        context,
        values["interface"],
        duration=values.get("duration"),
    )


def _stop(context: "AppContext", values: dict) -> str:
    return _service(context).stop(values["interface"])


def build_actions() -> list[Action]:
    return [
        Action(
            "lan.mac.flood",
            "Flood random-source MAC frames",
            "Continuously generate Ethernet frames with a randomized source MAC on "
            "every packet (macof-style Ether/IP/TCP) out the given interface, to "
            "test how a switch behaves when its CAM/MAC address table is saturated "
            "(requires root). The job runs in the background and the prompt stays "
            "usable; --duration stops it automatically after N seconds, otherwise "
            "stop it with 'lan mac stop <interface>'. Only one flood runs per "
            "interface at a time; use the top-level 'tasks' command to see what is "
            "running. While flooding, the interface is busy generating traffic. For "
            "authorized security testing only.",
            _flood,
            [
                Param("interface", "Interface to generate traffic on (e.g. eth0)"),
                Param("duration", "Stop automatically after N seconds", int,
                      required=False),
            ],
            ["lan mac flood eth0", "lan mac flood eth0 --duration 30"],
            requires_root=True,
        ),
        Action(
            "lan.mac.stop",
            "Stop a MAC flood",
            "Stop the MAC flood running on the given interface and report how many "
            "frames it sent (requires root).",
            _stop,
            [Param("interface", "Interface whose flood to stop (e.g. eth0)")],
            ["lan mac stop eth0"],
            requires_root=True,
        ),
    ]

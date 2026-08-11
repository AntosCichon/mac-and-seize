"""Actions for the ``l2 arp`` command group (ARP cache poisoning).

Two commands, both root-only: ``spoof`` starts a background job that
continuously injects forged ARP replies claiming a given IP is at a given MAC,
and ``stop`` ends every running spoof job. Handlers stay thin - they translate
parsed values into calls on the session-scoped
:class:`~mac_and_seize.modules.l2.arp.service.ArpSpoofService`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.l2.arp.service import ArpSpoofService

SERVICE = "l2_arp"

GROUP_DESCRIPTIONS = {
    "l2.arp": "ARP-layer automations (ARP cache poisoning)",
}


def _service(context: "AppContext") -> "ArpSpoofService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _spoof(context: "AppContext", values: dict) -> str:
    return _service(context).spoof(
        context,
        values["interface"],
        values["ip"],
        values["mac"],
        values["method"],
        target=values.get("target"),
    )


def _stop(context: "AppContext", values: dict) -> str:
    return _service(context).stop_all()


def build_actions() -> list[Action]:
    return [
        Action(
            "l2.arp.spoof",
            "Spoof ARP replies",
            "Continuously send forged ARP frames claiming that <ip> is at "
            "<mac>, so target hosts update their ARP caches and redirect "
            "traffic for <ip> to the given MAC (requires root). Frames leave "
            "<interface>, and <method> picks the delivery style: 'reply' "
            "sends one forged ARP reply per target - unicast to the target's "
            "MAC when known (e.g. from 'discovered'), else broadcast - which "
            "is what a victim expects to see after sending an ARP request; "
            "'gratuitous' sends one L2-broadcast frame per target subnet with "
            "'pdst' set to that subnet's directed broadcast, so a single "
            "frame announces the binding to every host on the segment (fewer "
            "packets, whole-segment reach). Either way --target chooses whom "
            "to poison and accepts a single IP, a CIDR (192.168.1.0/24), a "
            "last-octet range (192.168.1.10-20), or the keyword 'discovered' "
            "to reuse every host the discovery module has already found "
            "(gratuitous mode groups those addresses into /24 subnets to "
            "compute the broadcast pdst per subnet). The job runs in the "
            "background and the prompt stays usable; stop every running "
            "spoof with 'l2 arp stop'. Use the top-level 'tasks' command to "
            "see what is running. Several spoofs can run at once as long as "
            "they claim different (interface, ip) pairs. For authorized "
            "security testing only.",
            _spoof,
            [
                Param("interface", "Interface to send frames from (e.g. eth0)"),
                Param("ip", "IP address being claimed (the 'is at' address)"),
                Param("mac", "MAC address being claimed (e.g. AA:BB:CC:DD:EE:FF)"),
                Param(
                    "method",
                    "'reply' (one ARP reply per target) or 'gratuitous' (one "
                    "broadcast announcement per target subnet)",
                ),
                Param(
                    "target",
                    "Whom to poison: an IP, CIDR (a.b.c.0/24), range "
                    "(a.b.c.10-20), or 'discovered'",
                    required=False,
                ),
            ],
            [
                "l2 arp spoof eth0 192.168.1.1 aa:bb:cc:dd:ee:ff reply --target 192.168.1.100",
                "l2 arp spoof eth0 192.168.1.1 aa:bb:cc:dd:ee:ff reply --target 192.168.1.10-20",
                "l2 arp spoof eth0 192.168.1.1 aa:bb:cc:dd:ee:ff gratuitous --target 192.168.1.0/24",
                "l2 arp spoof eth0 192.168.1.1 aa:bb:cc:dd:ee:ff gratuitous --target discovered",
            ],
            requires_root=True,
        ),
        Action(
            "l2.arp.stop",
            "Stop all ARP spoofs",
            "Stop every running ARP spoof job and report how many reply frames "
            "were sent in total (requires root). There is no per-job stop "
            "command by design - see the top-level 'tasks' command for "
            "individual job identities.",
            _stop,
            [],
            ["l2 arp stop"],
            requires_root=True,
        ),
    ]

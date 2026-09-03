"""Actions exposed by the relay module.

Only view / stop commands: relay flows are *started* through the ``--relay`` /
``--nat-relay`` flags on the redirection modules (arp / dhcp / stp) which
each call the corresponding ``begin_*`` on the session-scoped
:class:`~mac_and_seize.modules.relay.service.RelayService`. This keeps the
module surface small and matches the coupling style the operator asked for:
"one command to start a redirection that also relays", not "start a
redirection then separately start a relay".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.relay.service import RelayService

SERVICE = "relay"

GROUP_DESCRIPTIONS = {
    "relay": "View and stop running traffic-relay flows",
}


def _service(context: "AppContext") -> "RelayService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _list(context: "AppContext", values: dict):
    rows = _service(context).list_rows()
    if not rows:
        return (
            "No relay flows are running. Start one by passing '--relay' to "
            "any command that supports MITM functionalities"
        )
    return rows


def _stop(context: "AppContext", values: dict) -> str:
    return _service(context).end_all()


def build_actions() -> list[Action]:
    return [
        Action(
            "relay.list",
            "List relay flows",
            "Show every relay flow currently running: its id, kind (l2-arp / "
            "l3-dhcp / l3-dhcp-nat / l2-straddle), engine (python / kernel), "
            "label, forwarded-frame count, send-failure streak, runtime, and - "
            "for kernel-NAT flows - the number of source addresses currently "
            "in the masquerade set. Relay flows are started implicitly by "
            "passing '--relay' (or '--nat-relay' on 'lan dhcp server') to a "
            "redirection command; there is no 'relay start' by design.",
            _list,
            [],
            ["relay list"],
        ),
        Action(
            "relay.stop",
            "Stop all relay flows",
            "Tear down every running relay flow, restore any sysctl the "
            "kernel-NAT engine forced, and delete the nftables tables of the "
            "relay. Relays coupled to a running attack job (arp / dhcp / "
            "stp) are stopped here too; the attack jobs themselves keep "
            "running - use their own stop commands to end them. Requires "
            "root because the underlying nftables and sysctl changes do.",
            _stop,
            [],
            ["relay stop"],
            requires_root=True,
        ),
    ]

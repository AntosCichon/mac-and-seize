"""Actions for the ``lan stp`` command group (STP reconnaissance and BPDU
injection).

Four commands, all root-only:

* ``learn`` blocks and listens for BPDUs on one interface, then reports the
  root bridge and the upstream switch. Reconnaissance; nothing is sent.
* ``spoof`` starts a background job that periodically claims to be the root
  bridge on one interface.
* ``dos`` starts a background job that either floods randomized configuration
  BPDUs (so the tree never converges) or, with ``--tcn``, floods
  topology-change notifications (so MAC-table aging stays permanently short).
* ``stop`` ends every running spoof / dos job.

Handlers stay thin - they translate parsed values into calls on the
session-scoped :class:`~mac_and_seize.modules.lan.stp.service.StpService`.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.lan.stp.service import StpService

SERVICE = "lan_stp"
GROUP_DESCRIPTIONS = {
    "lan.stp": "Spanning Tree Protocol reconnaissance and BPDU injection",
}


def _service(context: "AppContext") -> "StpService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _learn(context: "AppContext", values: dict) -> dict:
    return _service(context).learn(
        context, values["interface"], timeout=values.get("timeout"),
    )


def _spoof(context: "AppContext", values: dict) -> str:
    return _service(context).spoof(
        context,
        values["interface"],
        relay_egress=values.get("relay"),
    )


def _dos(context: "AppContext", values: dict) -> str:
    return _service(context).dos(
        context, values["interface"], tcn=bool(values.get("tcn")),
    )


def _stop(context: "AppContext", values: dict) -> str:
    return _service(context).stop_all()


def build_actions() -> list[Action]:
    return [
        Action(
            "lan.stp.learn",
            "Learn the STP topology on a port",
            "Listen for BPDUs on <interface> and, once the window closes, "
            "report the current root bridge on the segment (priority and MAC), "
            "the upstream switch this port is attached to (its bridge "
            "priority and MAC, plus the port ID it is using), and the "
            "advertised timers (hello time, max age, forward delay). Also "
            "shows how many configuration and topology-change BPDUs were "
            "seen in the window, and whether the upstream switch is itself "
            "the root. Blocks until --timeout elapses (default 8s) - long "
            "enough to observe several hellos and to notice an ongoing "
            "re-election, short enough not to feel hung. Nothing is sent; "
            "this is passive reconnaissance (requires root only because "
            "sniffing a link-layer socket does).",
            _learn,
            [
                Param("interface", "Interface to listen on (e.g. eth0)"),
                Param(
                    "timeout",
                    "Seconds to listen for BPDUs (default: 8)",
                    float,
                    required=False,
                ),
            ],
            ["lan stp learn eth0", "lan stp learn eth0 --timeout 20"],
            requires_root=True,
        ),
        Action(
            "lan.stp.spoof",
            "Spoof the root bridge",
            "Start a background job that periodically sends a configuration "
            "BPDU on <interface> claiming to be the root bridge at priority "
            "0 (the lowest, i.e. best, 802.1D priority). Frames use the "
            "own MAC of the interface as the bridge ID, so a peer already at "
            "priority 0 with a lower MAC still keeps the root - that is the "
            "802.1D tie-break and this command does not cheat it. Against "
            "any segment where every bridge is at default priority (32768) "
            "or a manually configured non-zero value, this wins within a "
            "few hello intervals and every path through the segment now "
            "goes through us. The prompt stays usable; use the top-level "
            "'tasks' command to see what is running. Only one STP job runs "
            "per interface; stop every running job with 'lan stp stop'. "
            "--relay <egress-iface> additionally starts a straddle relay "
            "that bridges frames verbatim between <interface> and the given "
            "egress NIC, matching the picture the spoofed root would see if "
            "physically inserted between two segments. The relay is a "
            "Python bridge and forwards at low tens of kpps at best; do "
            "not use it on a segment with real broadcast/multicast volume "
            "- for physically in-line taps use a kernel bridge outside "
            "this tool. The relay is torn down alongside the spoof (either "
            "explicitly via 'lan stp stop' or when this job self-terminates). "
            "For authorized security testing only.",
            _spoof,
            [
                Param("interface", "Interface to send BPDUs from (e.g. eth0)"),
                Param(
                    "relay",
                    "Straddle-bridge egress iface (Python bridge)",
                    str,
                    required=False,
                ),
            ],
            [
                "lan stp spoof eth0",
                "lan stp spoof eth0 --relay eth1",
            ],
            requires_root=True,
        ),
        Action(
            "lan.stp.dos",
            "Flood BPDUs to churn the tree",
            "Start a background job that floods BPDUs on <interface> to keep "
            "the segment in a permanent state of upheaval. In the default "
            "mode every emitted frame is a configuration BPDU with a fresh "
            "(random 802.1D priority, random locally-administered unicast "
            "MAC) identity, so no two frames agree on who the root is and "
            "the tree never gets a chance to converge - switches spend "
            "their time recomputing instead of forwarding. With --tcn the "
            "job emits topology-change notifications only, which is a "
            "gentler traffic rate but forces every switch on the segment to "
            "run its post-change short MAC-aging timer (forward delay, "
            "default 15s) continuously, so already-learned addresses keep "
            "expiring and unicast to them is flooded out every port. Only "
            "one STP job runs per interface; stop every running job with "
            "'lan stp stop'. WARNING: this is a denial of service on the "
            "whole segment. For authorized security testing only.",
            _dos,
            [
                Param("interface", "Interface to flood on (e.g. eth0)"),
                Param(
                    "tcn",
                    "Send only topology-change notifications (TCN BPDUs)",
                    bool,
                    required=False,
                    default=False,
                    is_flag=True,
                ),
            ],
            ["lan stp dos eth0", "lan stp dos eth0 --tcn"],
            requires_root=True,
        ),
        Action(
            "lan.stp.stop",
            "Stop all STP jobs",
            "Stop every running STP spoof and dos job and report how many "
            "BPDUs were sent in total (requires root). There is no per-job "
            "stop command by design - see the top-level 'tasks' command for "
            "individual job identities.",
            _stop,
            [],
            ["lan stp stop"],
            requires_root=True,
        ),
    ]

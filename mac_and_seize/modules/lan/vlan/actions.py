"""Actions for the ``lan vlan`` command group (DTP spoofing + 802.1Q hopping).

Four commands, all root-only:

* ``learn`` blocks and listens for DTP/CDP/802.1Q frames on one interface,
  then reports the neighbor's DTP mode, whether CDP is on the wire, and any
  VLAN IDs seen. Reconnaissance; nothing is sent.
* ``dtp-spoof`` starts a background job that periodically sends a DTP hello
  claiming trunking, so a switch port at ``dynamic auto``/``dynamic
  desirable`` flips to trunk.
* ``hop`` starts a background job that reinjects outbound frames destined to
  a target IP wrapped in two 802.1Q tags (the classic double-tag VLAN hop).
* ``stop`` ends every running VLAN job.

Handlers stay thin - they translate parsed values into calls on the
session-scoped :class:`~mac_and_seize.modules.lan.vlan.service.VlanService`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.lan.vlan.service import VlanService

SERVICE = "lan_vlan"

GROUP_DESCRIPTIONS = {
    "lan.vlan": "VLAN automations (DTP spoofing and 802.1Q hopping)",
}


def _service(context: "AppContext") -> "VlanService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _learn(context: "AppContext", values: dict) -> dict:
    return _service(context).learn(
        context, values["interface"], timeout=values.get("timeout"),
    )


def _dtp_spoof(context: "AppContext", values: dict) -> str:
    return _service(context).dtp_spoof(
        context, values["interface"], mode=values.get("mode"),
    )


def _hop(context: "AppContext", values: dict) -> str:
    return _service(context).hop(
        context,
        values["interface"],
        values["native-vlan"],
        values["inner-vlan"],
        values["target-ip"],
    )


def _stop(context: "AppContext", values: dict) -> str:
    return _service(context).stop_all()


def build_actions() -> list[Action]:
    return [
        Action(
            "lan.vlan.learn",
            "Learn VLAN/DTP state on a port",
            "Listen for VLAN-related traffic on <interface> and, once the "
            "window closes, report what the segment looks like from a VLAN "
            "point of view: whether a Dynamic Trunking Protocol (DTP) "
            "neighbor is present and, if so, its advertised mode (the "
            "status byte translated to 'desirable' / 'trunk' / 'unknown "
            "0x??'), its DTP domain, and the neighbor MAC it identifies "
            "itself as; whether Cisco Discovery Protocol (CDP) frames are "
            "on the wire (which carry a Native VLAN TLV a follow-up "
            "capture can read); and the set of 802.1Q VLAN IDs that "
            "appeared on the link during the window (any VLAN ID leaking "
            "onto an access port is evidence of a misconfigured trunk or "
            "a native-VLAN mismatch). Blocks until --timeout elapses "
            "(default 30s, one full Cisco DTP hello cycle) - long enough "
            "to reliably see one DTP hello in the worst case, short "
            "enough not to feel hung. Nothing is sent; this is passive "
            "reconnaissance (requires root only because sniffing a "
            "link-layer socket does). Run this before 'lan vlan dtp-spoof' "
            "to confirm the peer is negotiable, and before 'lan vlan hop' "
            "to see whether tagged frames leak (a strong hint at the "
            "native VLAN).",
            _learn,
            [
                Param("interface", "Interface to listen on (e.g. eth0)"),
                Param(
                    "timeout",
                    "Seconds to listen (default: 30, one DTP cycle)",
                    float,
                    required=False,
                ),
            ],
            [
                "lan vlan learn eth0",
                "lan vlan learn eth0 --timeout 60",
                "lan vlan learn eth0 --timeout 5",
            ],
            requires_root=True,
        ),
        Action(
            "lan.vlan.dtp-spoof",
            "Spoof DTP to flip a port to trunk",
            "Start a background job that periodically sends a Cisco Dynamic "
            "Trunking Protocol (DTP) hello on <interface> claiming this "
            "port is a trunk. A switch port at 'switchport mode dynamic "
            "auto' or 'switchport mode dynamic desirable' - Cisco's "
            "defaults on many older platforms - will negotiate with us and "
            "flip to trunk, opening every VLAN allowed on the trunk to "
            "frames tagged with the right VID. A port explicitly configured "
            "'switchport nonegotiate' or 'switchport mode access' ignores "
            "DTP and this command has no effect on it (which 'lan vlan "
            "learn' can tell you before you try). Hellos are sent every "
            "30 seconds - the same cadence a real Cisco switch uses - so "
            "the frame stream looks like a normal DTP neighbor and the "
            "port keeps the trunk state up for as long as the job runs. "
            "--mode picks the status the hellos advertise: 'desirable' "
            "(default; wins against both 'dynamic auto' and 'dynamic "
            "desirable' peers) or 'trunk' (an unconditional-trunk claim; "
            "fastest convergence against 'dynamic auto' but more obvious "
            "in a packet capture). The source MAC of every hello is the "
            "interface's own MAC, on purpose: a switch keys DTP neighbor "
            "state on it and changing MAC per frame would look like a "
            "stream of ghost neighbors instead of one persistent one. Only "
            "one DTP job runs per interface at a time; stop every running "
            "VLAN job with 'lan vlan stop'. The prompt stays usable; see "
            "the top-level 'tasks' command for what is running. DTP is a "
            "Cisco-proprietary protocol - this command has no effect on a "
            "switch from another vendor. Flipping a port to trunk changes "
            "the segment's fabric-level security posture; for authorized "
            "security testing only.",
            _dtp_spoof,
            [
                Param("interface", "Interface to send DTP hellos on (e.g. eth0)"),
                Param(
                    "mode",
                    "DTP mode to claim: 'desirable' (default) or 'trunk'",
                    required=False,
                ),
            ],
            [
                "lan vlan dtp-spoof eth0",
                "lan vlan dtp-spoof eth0 --mode trunk",
            ],
            requires_root=True,
        ),
        Action(
            "lan.vlan.hop",
            "Hop a VLAN via 802.1Q double-tagging",
            "Start a background job that keeps double-tagged frames flowing "
            "into <inner-vlan> for as long as it runs. A scapy sniffer on "
            "<interface> watches for outbound IPv4 frames the host itself "
            "emits toward <target-ip>, and reinjects each match wrapped in "
            "two stacked 802.1Q tags: outer = <native-vlan> (the native "
            "VLAN of the upstream trunk), inner = <inner-vlan> (the VLAN "
            "the target lives in). The first switch strips the outer tag "
            "because it matches the native VLAN of the trunk, forwards the "
            "now-single-tagged frame across the trunk, and the second "
            "switch honours the inner tag and delivers into <inner-vlan> - "
            "a VLAN the attacker's access port has no direct route to. "
            "The attack is *strictly one-way*: a reply from the target "
            "leaves via <inner-vlan>'s normal egress and does not travel "
            "back to us through the same trick.\n\n"
            "The user is expected to generate the outbound traffic that "
            "feeds this job (from another shell: 'ping <target-ip>', "
            "'curl http://<target-ip>', etc.). The *original* untagged "
            "frame still goes out on the wire - the kernel has already "
            "committed it by the time the sniffer sees it, and Python "
            "cannot cancel a frame in flight. The tagged copy is the "
            "one that hops; the untagged copy is dropped by the first "
            "switch (native-VLAN egress path has no route to the "
            "off-subnet target). Loop-safety: the sniffer's BPF (`outbound "
            "and ip and dst host <ip> and not vlan`) skips frames that "
            "already carry a Dot1Q tag, so our own reinjected traffic does "
            "not re-trigger us; a defensive Python-side Dot1Q check "
            "handles drivers that strip 802.1Q into PACKET_AUXDATA "
            "metadata.\n\n"
            "Preconditions the operator must verify: (1) the attacker's "
            "access port is assigned to <native-vlan> - if the trunk's "
            "native VLAN differs, the outer tag is not stripped and the "
            "hop silently fails (run 'lan vlan learn' to look for CDP "
            "Native VLAN TLVs or leaking tagged frames as a hint); (2) "
            "the target actually lives in <inner-vlan> on the far side "
            "of the trunk; (3) the upstream link is a trunk carrying "
            "<inner-vlan> in the first place (if the port is still "
            "access, run 'lan vlan dtp-spoof' first to try flipping it). "
            "Native and target VLAN must differ (a hop into the same "
            "VLAN is a no-op); the service refuses that up front. "
            "Only one hop job runs per (interface, target) pair at a "
            "time; stop every running VLAN job with 'lan vlan stop'. "
            "For authorized security testing only.",
            _hop,
            [
                Param("interface", "Interface to reinject on (e.g. eth0)"),
                Param(
                    "native-vlan",
                    "Outer tag VLAN (the trunk's native VLAN, 1-4094)",
                    int,
                ),
                Param(
                    "inner-vlan",
                    "Inner tag VLAN (the target VLAN to reach, 1-4094)",
                    int,
                ),
                Param(
                    "target-ip",
                    "Destination IP of traffic to tag (IPv4, e.g. 10.0.20.5)",
                ),
            ],
            [
                "lan vlan hop eth0 1 20 10.0.20.5",
                "lan vlan hop eth0 99 200 192.168.200.10",
            ],
            requires_root=True,
        ),
        Action(
            "lan.vlan.stop",
            "Stop all VLAN jobs",
            "Stop every running VLAN job (DTP spoofs and double-tag hop "
            "relays) and report how many DTP hellos and how many tagged "
            "frames were sent in total (requires root). There is no per-job "
            "stop command by design - see the top-level 'tasks' command "
            "for individual job identities.",
            _stop,
            [],
            ["lan vlan stop"],
            requires_root=True,
        ),
    ]

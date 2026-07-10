"""Actions exposed by the capture module (a single top-level ``capture``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.capture.service import CaptureService

SERVICE = "capture"


def _service(context: "AppContext") -> "CaptureService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _capture(context: "AppContext", values: dict):
    service = _service(context)
    count = values.get("count") or 0
    timeout = values.get("timeout")
    if count == 0 and timeout is None:
        raise ValueError("Provide a count and/or a timeout so the capture ends.")
    packets = service.sniff(
        values["iface"],
        count=count,
        bpf_filter=values.get("filter"),
        timeout=timeout,
    )
    if values.get("output") and packets:
        service.write_pcap(values["output"], packets)
    if not packets:
        return "No packets captured."
    return [packet.summary() for packet in packets]


def build_actions() -> list[Action]:
    return [
        Action(
            "capture",
            "Capture packets",
            "Sniff packets on an interface (requires root).",
            _capture,
            [
                Param("iface", "Interface to capture on (e.g. eth0)", multiple=True),
                Param("count", "Number of packets (0 = until timeout)", int,
                      required=False, default=0),
                Param("filter", "BPF filter (e.g. 'tcp port 80')", str,
                      required=False),
                Param("timeout", "Stop after N seconds", int, required=False),
                Param("output", "Save to pcap file path", str, required=False),
            ],
            [
                "capture eth0 --count 10",
                "capture eth0 --timeout 5 --filter 'tcp port 80' --output cap.pcap",
            ],
            requires_root=True,
        )
    ]

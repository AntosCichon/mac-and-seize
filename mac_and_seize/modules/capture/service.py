"""Send and capture packets on an interface (the capture module's service)."""

from __future__ import annotations

from pathlib import Path

from scapy.all import sniff, srp

from mac_and_seize.modules.capture.net import Packet, write_pcap
from mac_and_seize.observability import get_logger


class CaptureService:
    """Packet send/sniff operations, keyed by interface name.

    These operations require root; callers are expected to have ensured
    privileges (the CLI gates root-only actions before running them).
    """

    def __init__(self) -> None:
        self._log = get_logger(__name__)

    def send(self, iface_name: str, packet: Packet, *, timeout: int = 5):
        """Send a packet and wait for a response at layer 2."""
        pkt = packet.build() if isinstance(packet, Packet) else packet
        self._log.info("Sending packet on %s: %s", iface_name, packet)
        answered, unanswered = srp(
            pkt, iface=iface_name, threaded=False, timeout=timeout, verbose=False
        )
        self._log.info(
            "Send complete on %s: %d answered, %d unanswered",
            iface_name,
            len(answered),
            len(unanswered),
        )
        return answered, unanswered

    def sniff(
        self,
        iface_name: str,
        *,
        count: int = 0,
        bpf_filter: str | None = None,
        timeout: int | None = None,
    ) -> list[Packet]:
        """Capture packets on an interface, returning wrapped ``Packet``s."""
        self._log.info(
            "Sniffing on %s (count=%s, filter=%s, timeout=%s)",
            iface_name,
            count,
            bpf_filter,
            timeout,
        )
        captured = sniff(
            iface=iface_name, filter=bpf_filter, timeout=timeout, count=count
        )
        self._log.info("Captured %d packet(s) on %s", len(captured), iface_name)
        return [Packet.from_scapy(pkt) for pkt in captured]

    def write_pcap(
        self, path: str | Path, packets: list[Packet], *, append: bool = True
    ) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_pcap(str(path), packets, append=append)
        self._log.info("Wrote %d packet(s) to %s", len(packets), path)
        return path

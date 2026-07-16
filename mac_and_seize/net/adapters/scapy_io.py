"""Packet I/O over scapy: send, one-shot sniff, pcap read/write, NIC listing.

The generic (non-session) packet I/O that any module can reuse. Background
capture lifecycle (scapy's ``AsyncSniffer``) stays with the capture module,
since that is stateful session behaviour rather than a plain operation.
"""

from __future__ import annotations

from scapy.all import get_if_list, sniff as _sniff, srp
from scapy.utils import rdpcap, wrpcap

from mac_and_seize.net.model.packet import Packet


def available_interfaces() -> list[str]:
    """Return the interfaces scapy can sniff/send on."""
    return get_if_list()


def send(iface_name: str, packet: Packet, *, timeout: int = 5):
    """Send a packet and wait for a response at layer 2 (scapy ``srp``).

    Returns scapy's ``(answered, unanswered)`` pair.
    """
    pkt = packet.build() if isinstance(packet, Packet) else packet
    return srp(pkt, iface=iface_name, threaded=False, timeout=timeout, verbose=False)


def sniff(
    iface_name: str,
    *,
    count: int = 0,
    bpf_filter: str | None = None,
    timeout: int | None = None,
) -> list[Packet]:
    """Capture packets synchronously (one-shot); returns wrapped packets."""
    captured = _sniff(iface=iface_name, filter=bpf_filter, timeout=timeout, count=count)
    return [Packet.from_scapy(pkt) for pkt in captured]


def write_pcap(filename: str, packets: list, append: bool = True) -> None:
    """Write packets (``Packet`` or raw scapy) to a pcap file."""
    wrpcap(
        filename,
        [p.pcap() if isinstance(p, Packet) else p for p in packets],
        append=append,
    )


def read_pcap(filename: str) -> list[Packet]:
    """Read a pcap file, returning wrapped :class:`Packet`s."""
    return [Packet.from_scapy(pkt) for pkt in rdpcap(filename)]

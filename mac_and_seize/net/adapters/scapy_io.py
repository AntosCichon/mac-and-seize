"""Packet I/O over scapy: send, one-shot sniff, pcap read/write, NIC listing,
and host discovery (ARP sweeps).

The generic (non-session) packet I/O that any module can reuse. Background
capture lifecycle (scapy's ``AsyncSniffer``) stays with the capture module,
since that is stateful session behaviour rather than a plain operation.
"""

from __future__ import annotations

import ipaddress
import logging
import re

from scapy.all import ARP, Ether, conf, get_if_list, sniff as _sniff, srp
from scapy.utils import rdpcap, wrpcap

from mac_and_seize.net.model.packet import Packet

# scapy logs benign, per-packet notices through its own ``scapy.runtime`` logger
# straight to stderr, from whichever worker thread is sending - which during an
# interactive session would print right onto the live prompt. These are noise
# for this tool, so raise the level to drop scapy's WARNINGs from the console;
# genuine scapy ERRORs still surface and our own file logging is unaffected.
# See modules/README.md §9 on not disturbing the prompt.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# A last-octet range such as ``192.168.1.10-20``. scapy's ``Net`` accepts a
# single address or CIDR but rejects ``a-b`` ranges, so we expand this one
# common form ourselves into an explicit address list.
_LAST_OCTET_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")

# Upper bound on how many addresses a single scan target may expand to. Guards
# against an accidental huge sweep (a /8 is ~16M hosts); a /16 still fits.
_MAX_HOSTS = 65536


def available_interfaces() -> list[str]:
    """Return the interfaces scapy can sniff/send on."""
    return get_if_list()


def refresh_interfaces() -> None:
    """Rebuild scapy's interface cache so newly-created NICs are visible.

    scapy resolves an interface *name* to its ``ifindex`` through a cache
    (``conf.ifaces``) built at import time. A monitor interface created at
    command time is therefore absent (or a same-named one deleted and recreated
    now carries a stale ifindex), and sniffing on it fails with ``ENODEV``
    ([Errno 19] No such device). Call this right after adding or re-typing an
    interface, before opening a socket on it.
    """
    conf.ifaces.reload()


def expand_hosts(target: str) -> list[str]:
    """Expand a scan ``target`` into an explicit list of host addresses.

    Accepts a single IP or hostname (one host), a CIDR (``192.168.1.0/24``), or
    a last-octet range (``192.168.1.10-20``). For a CIDR the network and
    broadcast addresses are excluded - only assignable hosts are probed. The
    size is derived from the prefix and checked *before* any address is
    enumerated, so an oversized target is rejected cheaply instead of first
    materialising a huge list. Raises :class:`ValueError` for malformed input
    (including an out-of-range octet such as ``999.1.1.1``) or a target larger
    than :data:`_MAX_HOSTS`.
    """
    target = target.strip()
    match = _LAST_OCTET_RANGE.match(target)
    if match:
        prefix, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
        if lo > hi or hi > 255:
            raise ValueError(f"Invalid address range {target!r}.")
        hosts = [f"{prefix}{octet}" for octet in range(lo, hi + 1)]
        # The regex only bounds each octet to 1-3 digits, so the three prefix
        # octets could still be >255 (``999.1.1.1``). Validate the assembled
        # endpoints - the prefix is constant and every last octet is within the
        # checked [lo, hi] <= 255, so valid endpoints imply the whole range is.
        for endpoint in (hosts[0], hosts[-1]):
            try:
                ipaddress.ip_address(endpoint)
            except ValueError as exc:
                raise ValueError(f"Invalid address range {target!r}: {exc}") from exc
        return hosts
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid target {target!r}: {exc}") from exc
        # num_addresses comes from the prefix (O(1)), so an oversized range is
        # rejected without enumerating a single address.
        if network.num_addresses > _MAX_HOSTS:
            raise ValueError(
                f"Target {target!r} covers {network.num_addresses} addresses; "
                f"the limit is {_MAX_HOSTS}. Scan a smaller range."
            )
        # hosts() omits the network and broadcast address of a normal subnet
        # (and still yields the address(es) of a /31 or /32).
        return [str(ip) for ip in network.hosts()]
    return [target]


def arp_probe(
    hosts: list[str], *, timeout: float = 0.5, iface: str | None = None
) -> dict[str, str]:
    """ARP-probe ``hosts`` (an explicit address list); return ``{ip: mac}``.

    Sends a broadcast ARP request for each address and collects the replies.
    Only works on the local subnet (ARP is not routed). ``iface`` pins the
    probe to a specific NIC (needed on a multi-homed host so the requests leave
    the interface that is actually on the target subnet); ``None`` lets scapy
    pick its default. A ``filter="arp"`` BPF is installed on the receive socket
    so the sniffer only pulls ARP frames off the link (and Python-matches only
    those), instead of every frame on a busy segment. The probe design mirrors
    nmap's ARP host discovery (``-PR``); the implementation here is an original
    scapy composition, not derived from nmap's source.
    """
    if not hosts:
        return {}
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=hosts),
        timeout=timeout,
        iface=iface,
        filter="arp",
        verbose=False,
    )
    found: dict[str, str] = {}
    for _sent, received in answered:
        found.setdefault(received.psrc, received.hwsrc)
    return found


def mac_vendor(mac: str | None) -> str | None:
    """Best-effort OUI vendor lookup for a MAC via scapy's manufacturer DB.

    Returns ``None`` when the OUI isn't known: scapy echoes the address back
    (the full MAC, or just its OUI prefix) instead of a name in that case, and
    we must not mistake that for a vendor.
    """
    if not mac:
        return None
    try:
        vendor = conf.manufdb._get_manuf(mac)
    except Exception:  # noqa: BLE001 - lookup is optional; never fail a scan over it
        return None
    if not vendor:
        return None
    normalized_mac = mac.replace(":", "").replace("-", "").lower()
    normalized_vendor = vendor.replace(":", "").replace("-", "").lower()
    if normalized_mac.startswith(normalized_vendor):
        return None  # scapy returned the address itself, not a vendor name
    return vendor


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

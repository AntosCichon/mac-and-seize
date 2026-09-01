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

from scapy.all import (
    ARP,
    ICMP,
    IP,
    TCP,
    UDP,
    AsyncSniffer,
    Ether,
    conf,
    get_if_list,
    sendp as _sendp,
    sniff as _sniff,
    sr,
    srp,
)
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


def refresh_network_state() -> None:
    """Rebuild scapy's cached interface *and* routing tables from the live system.

    scapy snapshots the interface list (``conf.ifaces``) and the kernel routing
    tables (``conf.route`` / ``conf.route6``) once, at import time - i.e. when the
    app launches. If the network changes afterwards (a cable moved to another NIC,
    an interface brought up or down, an address reassigned), that snapshot goes
    stale in two ways that both break a scan:

    * an *interface-pinned* sweep (``discovery scan ens37``) resolves the NIC name
      through the cached ``conf.ifaces`` and can pick up a stale/wrong ifindex, so
      the probe leaves the wrong link - finding nothing real (and sometimes a
      phantom reply from the stale path);
    * an *unpinned* (routed) sweep (``discovery scan 192.168.1.0/24``) chooses its
      egress from the cached routing table, which still points at the old
      interface, so the probes go out a now-dead NIC and every host looks down.

    Resyncing both right before a scan makes it send over whatever is actually up
    now. Reads ``/proc`` only - cheap and needs no privileges.
    """
    conf.ifaces.reload()
    conf.route.resync()
    try:
        conf.route6.resync()
    except Exception:  # noqa: BLE001 - IPv6 routing is optional; never fail a scan over it
        pass


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
    hosts: list[str],
    *,
    timeout: float = 1.0,
    retries: int = 2,
    iface: str | None = None,
) -> dict[str, str]:
    """ARP-probe ``hosts`` (an explicit address list); return ``{ip: mac}``.

    Sends a broadcast ARP request for each address and collects the replies.
    Only works on the local subnet (ARP is not routed). ``iface`` pins the
    probe to a specific NIC (needed on a multi-homed host so the requests leave
    the interface that is actually on the target subnet); ``None`` lets scapy
    pick its default. A ``filter="arp"`` BPF is installed on the receive socket
    so the sniffer only pulls ARP frames off the link (and Python-matches only
    those), instead of every frame on a busy segment.

    An ARP request (or its reply) can be dropped in transit, which would silently
    lose a host, so each address is probed up to ``retries`` + 1 times: every
    round re-probes only the addresses still unanswered, and the loop stops early
    once every address has replied. The probe design mirrors nmap's ARP host
    discovery (``-PR``); the implementation here is an original scapy composition,
    not derived from nmap's source.
    """
    if not hosts:
        return {}
    found: dict[str, str] = {}
    # dedup while preserving order; only unanswered addresses carry to next round.
    remaining = list(dict.fromkeys(hosts))
    for _attempt in range(retries + 1):
        if not remaining:
            break
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=remaining),
            timeout=timeout,
            iface=iface,
            filter="arp",
            verbose=False,
        )
        for _sent, received in answered:
            found.setdefault(received.psrc, received.hwsrc)
        remaining = [ip for ip in remaining if ip not in found]
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


# Default reliability knobs shared by the TCP/UDP port scans. A single burst of
# many probes loses replies (the receive path or the kernel's ICMP rate limiter
# can't keep up), which reads back as "no open ports" on a wide range even though
# the same ports scanned individually answer fine. So each port is probed up to
# ``_DEFAULT_SCAN_RETRIES`` + 1 times (only the still-silent ports carry to the
# next round), and a small inter-packet gap paces the send so the burst doesn't
# outrun the reply path.
_DEFAULT_SCAN_RETRIES = 2
_DEFAULT_SCAN_INTER = 0.001

# TCP header flag bits (RFC 793) used to classify a SYN-scan reply.
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_ACK = 0x10
_TCP_SYN_ACK = _TCP_SYN | _TCP_ACK

# ICMP "destination unreachable" (type 3) codes. Port-unreachable means a UDP
# port is closed; the admin/host/net-prohibited codes mean a firewall dropped
# the probe (filtered) rather than the port being closed.
_ICMP_UNREACHABLE = 3
_ICMP_PORT_UNREACHABLE = 3
_ICMP_FILTERED_CODES = {1, 2, 9, 10, 13}


def tcp_syn_scan(
    host: str,
    ports: list[int],
    *,
    timeout: float = 2.0,
    retries: int = _DEFAULT_SCAN_RETRIES,
    inter: float = _DEFAULT_SCAN_INTER,
) -> dict[int, str]:
    """TCP SYN-scan one ``host`` across ``ports``; return ``{port: state}``.

    Sends a lone SYN to each port (a half-open scan - the handshake is never
    completed) and classifies the reply: a SYN/ACK means the port is ``"open"``,
    a RST means ``"closed"``, and an ICMP unreachable means ``"filtered"``. Ports
    that never answer are *absent* from the result (the caller treats silence as
    filtered). Unlike an ARP sweep this runs at layer 3, so it is *routed*: the
    egress interface is chosen by the routing table (there is no ``iface`` pin -
    scapy's L3 ``sr`` ignores it), and it can reach hosts beyond the local link.

    A SYN or its reply can be dropped when many probes go out at once, which would
    silently miss an open port, so each port is probed up to ``retries`` + 1 times
    and ``inter`` paces the send (see :data:`_DEFAULT_SCAN_RETRIES` /
    :data:`_DEFAULT_SCAN_INTER`): every round re-probes only the ports still
    without a definitive (open/closed/filtered) answer, and the loop stops early
    once none remain. Mirrors nmap's ``-sS`` SYN scan; the implementation is an
    original scapy composition. Needs raw-socket access.
    """
    if not ports:
        return {}
    states: dict[int, str] = {}
    remaining = list(dict.fromkeys(ports))
    for _attempt in range(retries + 1):
        if not remaining:
            break
        answered, _ = sr(
            IP(dst=host) / TCP(dport=remaining, flags="S"),
            timeout=timeout,
            inter=inter,
            verbose=False,
        )
        for sent, received in answered:
            dport = int(sent[TCP].dport)
            if received.haslayer(TCP):
                flags = int(received[TCP].flags)
                if (flags & _TCP_SYN_ACK) == _TCP_SYN_ACK:
                    states[dport] = "open"
                elif flags & _TCP_RST:
                    states[dport] = "closed"
            elif received.haslayer(ICMP) and int(received[ICMP].type) == _ICMP_UNREACHABLE:
                states[dport] = "filtered"
        # Only ports still without any answer are worth re-probing.
        remaining = [port for port in remaining if port not in states]
    return states


def udp_scan(
    host: str,
    ports: list[int],
    *,
    timeout: float = 2.0,
    retries: int = _DEFAULT_SCAN_RETRIES,
    inter: float = _DEFAULT_SCAN_INTER,
) -> dict[int, str]:
    """UDP-scan one ``host`` across ``ports``; return ``{port: state}``.

    Sends an empty UDP datagram to each port and classifies the reply: a UDP
    response means ``"open"``; an ICMP port-unreachable (type 3, code 3) means
    ``"closed"``; another ICMP unreachable (admin/host/net-prohibited) means
    ``"filtered"``. Ports that never answer are *absent* - UDP silence is
    ambiguous (open or filtered), so the caller records those as
    ``open|filtered``.

    The kernel rate-limits outgoing ICMP errors, so scanning many ports in one
    burst leaves some closed ports looking unanswered (and an open service's lone
    reply can itself be dropped). Each port is therefore probed up to ``retries``
    + 1 times with an ``inter`` gap pacing the send (see
    :data:`_DEFAULT_SCAN_RETRIES` / :data:`_DEFAULT_SCAN_INTER`): every round
    re-probes only the ports still without a reply, so a definitive result has
    several chances to arrive under the rate limiter. Runs at layer 3 (routed,
    egress chosen by the routing table) and needs raw-socket access.
    """
    if not ports:
        return {}
    states: dict[int, str] = {}
    remaining = list(dict.fromkeys(ports))
    for _attempt in range(retries + 1):
        if not remaining:
            break
        answered, _ = sr(
            IP(dst=host) / UDP(dport=remaining),
            timeout=timeout,
            inter=inter,
            verbose=False,
        )
        for sent, received in answered:
            dport = int(sent[UDP].dport)
            if received.haslayer(UDP):
                states[dport] = "open"
            elif received.haslayer(ICMP):
                icmp = received[ICMP]
                if int(icmp.type) == _ICMP_UNREACHABLE:
                    code = int(icmp.code)
                    if code == _ICMP_PORT_UNREACHABLE:
                        states[dport] = "closed"
                    elif code in _ICMP_FILTERED_CODES:
                        states[dport] = "filtered"
        # Silent ports (still ambiguous open|filtered) get another chance.
        remaining = [port for port in remaining if port not in states]
    return states


def send(iface_name: str | None, packet: Packet, *, timeout: int = 5):
    """Send a packet and wait for a response at layer 2 (scapy ``srp``).

    ``iface_name`` pins the send to a specific NIC; pass ``None`` to let scapy
    choose the default egress interface from its routing table. Returns scapy's
    ``(answered, unanswered)`` pair.
    """
    pkt = packet.build() if isinstance(packet, Packet) else packet
    return srp(pkt, iface=iface_name, threaded=False, timeout=timeout, verbose=False)


def send_l2(frame, iface_name: str, *, count: int = 1) -> None:
    """Fire-and-forget layer-2 injection: send ``frame`` and await no reply.

    Unlike :func:`send` (which uses ``srp`` to send *and* receive), this is a
    one-way ``sendp`` used to inject raw link-layer frames - e.g. 802.11
    management frames on a monitor-mode interface, where no reply is expected.
    ``frame`` is a fully-built scapy packet (already wrapped in its link layer,
    such as ``RadioTap``); ``iface_name`` pins the send to that NIC. Verbose
    output is suppressed so nothing lands on the interactive prompt.
    """
    _sendp(frame, iface=iface_name, count=count, verbose=False)


def dispatch_sniffer(
    iface_name: str,
    handler,
    *,
    bpf_filter: str | None = None,
    ignore_outgoing: bool = False,
):
    """Build (but don't start) a background sniffer that *dispatches* frames.

    Unlike :func:`sniff` and the store-backed
    :class:`~mac_and_seize.net.session.PacketSession`, nothing is accumulated:
    each frame is handed to ``handler`` as it arrives and then dropped
    (``store=False``). That suits a protocol conversation - where a frame is
    only interesting for as long as it takes to answer it, and holding every
    frame of a long-running exchange would just grow without bound.

    ``handler`` runs on the sniffer's own thread, so it must be quick and must
    never write to stdout/stderr (see modules/README.md §9). The caller owns the
    lifecycle: ``.start()`` it, and ``.stop()`` it when done.

    Frames the host itself sends are seen here too by default: scapy's
    ``AsyncSniffer`` uses :class:`~scapy.arch.linux.L2ListenSocket`, whose
    ``recv_raw`` does not skip ``PACKET_OUTGOING`` (verified against
    scapy 2.7's ``arch/linux.py``). A handler that also *transmits* has to
    recognise and skip its own traffic or it will answer itself. For a
    verbatim-forwarding relay (STP straddle) the self-echo would loop, so
    pass ``ignore_outgoing=True`` to switch to :class:`L2Socket` (which does
    filter outgoing at the ``recv_raw`` boundary via
    ``sa_ll[2] == PACKET_OUTGOING``).
    """
    kwargs: dict = dict(
        iface=iface_name, filter=bpf_filter, prn=handler, store=False,
    )
    if ignore_outgoing:
        kwargs["L2socket"] = conf.L2socket
    sniffer = AsyncSniffer(**kwargs)
    return sniffer


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

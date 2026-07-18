"""Structured 802.11 capture filters and the include/exclude matching engine.

The wireless analogue of :mod:`mac_and_seize.modules.capture.filters`: a
:class:`WirelessFilter` is one atomic ``(action, field, value)`` rule over a
monitor-mode frame, and the engine compiles a set of them into a scapy
``lfilter`` with the same semantics as the wired one:

* an **exclude** match always drops the frame (exclude overrides include);
* otherwise, if any **include** filters exist, the frame is kept only if it
  matches at least one (OR across includes);
* with no include filters, everything not excluded is kept.

The fields are the ones that make sense for raw 802.11: ``bssid`` (the network's
addr3), ``ssid`` (from the SSID information element, management frames only),
and ``type``/``subtype`` (mgmt/ctrl/data and beacon/probe-req/deauth/...).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from scapy.layers.dot11 import Dot11, Dot11Elt

# --- Vocabulary (also used to validate user input) ---

ACTIONS = ("include", "exclude")
FIELDS = ("bssid", "ssid", "type", "subtype")

# Frame type names -> nl80211/802.11 type number.
TYPE_NAMES: dict[str, int] = {"mgmt": 0, "ctrl": 1, "data": 2}

# Frame subtype names -> ``(type, subtype)`` (subtype numbers repeat across
# types, so both are needed to match unambiguously).
SUBTYPE_NAMES: dict[str, tuple[int, int]] = {
    "assoc-req": (0, 0), "assoc-resp": (0, 1), "reassoc-req": (0, 2),
    "reassoc-resp": (0, 3), "probe-req": (0, 4), "probe-resp": (0, 5),
    "beacon": (0, 8), "disassoc": (0, 10), "auth": (0, 11), "deauth": (0, 12),
    "action": (0, 13),
    "bar": (1, 8), "ba": (1, 9), "ps-poll": (1, 10), "rts": (1, 11),
    "cts": (1, 12), "ack": (1, 13),
    "data": (2, 0), "null": (2, 4), "qos-data": (2, 8), "qos-null": (2, 12),
}


def _ssid(pkt) -> str | None:
    """SSID from the frame's information elements (management frames only)."""
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            try:
                return elt.info.decode(errors="replace")
            except Exception:  # noqa: BLE001
                return None
        elt = elt.payload.getlayer(Dot11Elt)
    return None


@dataclass
class WirelessFilter:
    """One 802.11 capture rule: ``action`` applied to a ``field``."""

    id: int
    action: str
    field: str
    value: str

    def matches(self, pkt) -> bool:
        """Whether ``pkt`` satisfies this rule (defensive: never raises)."""
        try:
            dot11 = pkt.getlayer(Dot11)
            if dot11 is None:
                return False
            if self.field == "bssid":
                return bool(dot11.addr3) and str(dot11.addr3).lower() == self.value.lower()
            if self.field == "ssid":
                ssid = _ssid(pkt)
                return ssid is not None and ssid == self.value
            if self.field == "type":
                number = TYPE_NAMES.get(self.value.lower())
                return number is not None and int(dot11.type) == number
            if self.field == "subtype":
                pair = SUBTYPE_NAMES.get(self.value.lower())
                return pair is not None and (int(dot11.type), int(dot11.subtype)) == pair
        except Exception:  # noqa: BLE001 - a malformed frame must not crash sniff
            return False
        return False

    def as_row(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "field": self.field,
            "value": self.value,
        }


def build_wireless_predicate(filters: list["WirelessFilter"]) -> Callable[[object], bool]:
    """Compile ``filters`` into a scapy ``lfilter`` predicate (see module docs)."""
    includes = [f for f in filters if f.action == "include"]
    excludes = [f for f in filters if f.action == "exclude"]

    def predicate(pkt) -> bool:
        if any(f.matches(pkt) for f in excludes):
            return False
        if includes:
            return any(f.matches(pkt) for f in includes)
        return True

    return predicate

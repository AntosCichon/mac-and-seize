"""The ``Host`` record and host-discovery probe methods.

``Host`` is module-internal state - the facts a scan reports about a live
address - kept only by the discovery module, the same way capture's ``Filter``
is kept only by capture (see ``modules/README.md`` §8).

The method names are *inspired by* nmap's host-discovery options (``-PR`` ARP,
``-PE`` ICMP echo); the actual probing is a pure-scapy implementation (see
:mod:`mac_and_seize.net.adapters.scapy_io`), not nmap.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: The individual probe methods a host can be found by, in the order ``all``
#: tries them. ``"arp"`` -> ARP request (local subnet only; yields a MAC),
#: ``"ping"`` -> ICMP echo (routed; IP only).
PROBE_METHODS: tuple[str, ...] = ("arp", "ping")

#: The ``--method`` keywords the user may pass, mapped to the probe method(s)
#: each runs. ``"all"`` tries every probe, stopping at the first that finds a
#: given host up (the remaining methods are skipped for that host).
METHODS: dict[str, tuple[str, ...]] = {
    "arp": ("arp",),
    "ping": ("ping",),
    "all": PROBE_METHODS,
}


@dataclass
class Host:
    """One discovered live host, keyed by IP in the session store."""

    ip: str
    mac: str | None
    vendor: str | None
    state: str
    method: str  # the probe method that actually found this host up
    first_seen: datetime
    last_seen: datetime

    def as_row(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac or "-",
            "vendor": self.vendor or "-",
            "state": self.state,
            "method": self.method,
            "first_seen": self.first_seen.strftime("%H:%M:%S"),
            "last_seen": self.last_seen.strftime("%H:%M:%S"),
        }

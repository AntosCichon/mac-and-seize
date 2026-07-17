"""The ``Host`` record for the discovery module's session store.

``Host`` is module-internal state - the facts a scan reports about a live
address - kept only by the discovery module, the same way capture's ``Filter``
is kept only by capture (see ``modules/README.md`` §8).

Hosts are found by a pure-scapy ARP sweep (inspired by nmap's ``-PR``, but
using none of nmap's code; see :mod:`mac_and_seize.net.adapters.scapy_io`), or
imported from a pcap. ``Host.method`` records which - ``"arp"`` or ``"pcap"``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Host:
    """One discovered live host, keyed by IP in the session store."""

    ip: str
    mac: str | None
    vendor: str | None
    state: str
    method: str  # how this host was found: "arp" (scan) or "pcap" (import)
    first_seen: datetime
    last_seen: datetime

    def as_row(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac or "-",
            "vendor": self.vendor or "-",
            "method": self.method,
            "first_seen": self.first_seen.strftime("%H:%M:%S"),
            "last_seen": self.last_seen.strftime("%H:%M:%S"),
        }

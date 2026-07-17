"""The ``Host`` record for the discovery module's session store.

``Host`` is module-internal state - the facts a scan reports about a live
address - kept only by the discovery module, the same way capture's ``Filter``
is kept only by capture (see ``modules/README.md`` §8).

Hosts are found by a pure-scapy ARP sweep (inspired by nmap's ``-PR``, but
using none of nmap's code; see :mod:`mac_and_seize.net.adapters.scapy_io`), or
imported from a pcap. ``Host.method`` records which - ``"arp"`` or ``"pcap"``.

The store keys a ``Host`` per IP, but for display :func:`aggregate_rows`
collapses the records into one row per MAC (a single NIC bound to several
addresses is one physical host), with the MAC column first.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
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


def _ip_sort_key(ip: str) -> tuple:
    """Order IP strings numerically (``.5`` before ``.10``), v4 before v6.

    The version is part of the key so a MAC bound to both IPv4 and IPv6 doesn't
    hit the ``IPv4Address``/``IPv6Address`` comparison error; anything that isn't
    a valid address (shouldn't occur) sorts last by string.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (0, addr.version, addr)
    except ValueError:
        return (1, 0, ip)


def aggregate_rows(hosts: Iterable[Host]) -> list[dict]:
    """Collapse discovered hosts into display rows, MAC column first.

    Several IPs behind one MAC are the same physical host (one NIC bound to
    multiple addresses), so they fold into a single row with the IPs joined.
    Hosts with no known MAC can't be grouped that way, so each keeps its own
    row. Rows follow first-appearance order; within a row the IPs are sorted
    numerically, and ``first_seen``/``last_seen`` span the whole group.
    """
    groups: dict[object, list[Host]] = {}
    for host in hosts:
        # A real MAC groups its addresses together; a missing MAC keys per IP so
        # unknown hosts never merge into one another.
        key = host.mac if host.mac else ("", host.ip)
        groups.setdefault(key, []).append(host)

    rows: list[dict] = []
    for members in groups.values():
        ips = sorted((h.ip for h in members), key=_ip_sort_key)
        rows.append({
            "mac": members[0].mac or "-",
            "ip": ", ".join(ips),
            "vendor": next((h.vendor for h in members if h.vendor), None) or "-",
            "method": ", ".join(sorted({h.method for h in members})),
            "first_seen": min(h.first_seen for h in members).strftime("%H:%M:%S"),
            "last_seen": max(h.last_seen for h in members).strftime("%H:%M:%S"),
        })
    return rows

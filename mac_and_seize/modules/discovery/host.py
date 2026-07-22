"""The records for the discovery module's single, host-oriented store.

The discovery module keeps **one** store: a :class:`Host` per IP address. A host
is found by a pure-scapy ARP sweep (inspired by nmap's ``-PR``, but using none of
nmap's code; see :mod:`mac_and_seize.net.adapters.scapy_io`), imported from a
pcap, or implied by a port scan that finds an open port on it. ``Host.method``
records which - ``"arp"``, ``"pcap"``, or ``"port"``.

Port scans don't get their own list: an open port is a :class:`Port` attached to
the host it belongs to (``Host.ports``), keyed by ``(proto, port)`` so a repeat
scan refreshes an existing entry instead of duplicating it. This keeps everything
host-oriented - :func:`host_rows` renders one row per host, its open ports joined
into a single column (see :func:`format_ports`).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Port:
    """One open service on a host, keyed by ``(proto, port)`` in ``Host.ports``."""

    proto: str  # "tcp" or "udp"
    port: int
    state: str  # "open", or "open|filtered" (UDP with no reply)
    first_seen: datetime
    last_seen: datetime


@dataclass
class Host:
    """One discovered host, keyed by IP in the single discovery store.

    ``state`` is the host's liveness *relative to the most recent host scan*
    (see :meth:`~mac_and_seize.modules.discovery.service.DiscoveryService._merge_scan_locked`):

    * ``"up"`` - replied to the most recent scan;
    * ``"down"`` - was already known and its address was in the most recent
      scan's range, but it did not reply;
    * ``"N/A"`` - was already known but its address was not in the most recent
      scan's range, so its current liveness is unknown.

    ``is_new`` marks a host first discovered by the most recent scan (shown with
    a ``*`` prefix on its address); the scan clears it on every other host.
    """

    ip: str
    mac: str | None
    vendor: str | None
    state: str
    method: str  # how this host was found: "arp", "pcap", or "port"
    first_seen: datetime
    last_seen: datetime
    #: Open ports found on this host by a scan, keyed by ``(proto, port)``.
    ports: dict[tuple[str, int], Port] = field(default_factory=dict)
    #: First seen by the most recent scan (rendered with a ``*`` address prefix).
    is_new: bool = False


def _ip_sort_key(ip: str) -> tuple:
    """Order IP strings numerically (``.5`` before ``.10``), v4 before v6.

    The version is part of the key so a mixed v4/v6 store doesn't hit the
    ``IPv4Address``/``IPv6Address`` comparison error; anything that isn't a valid
    address (shouldn't occur) sorts last by string.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (0, addr.version, addr)
    except ValueError:
        return (1, 0, ip)


def format_ports(ports: dict[tuple[str, int], Port]) -> str:
    """Join a host's open ports into one column, e.g. ``22/tcp, 53/udp?``.

    Ports are ordered by protocol then number. A trailing ``?`` marks a UDP port
    whose state is ``open|filtered`` (it never replied, so open and firewalled
    can't be told apart). ``"-"`` when the host has no open ports.
    """
    if not ports:
        return "-"
    ordered = sorted(ports.values(), key=lambda p: (p.proto, p.port))
    return ", ".join(
        f"{p.port}/{p.proto}{'?' if p.state == 'open|filtered' else ''}"
        for p in ordered
    )


def host_rows(hosts: Iterable[Host]) -> list[dict]:
    """Render the store as full display rows, one per host, ordered by IP.

    Each row is ``{ip, state, mac, vendor, ports}``, folding the host's open
    ports into a single ``ports`` column (see :func:`format_ports`). ``state`` is
    the host's liveness versus the most recent scan (``up``/``down``/``N/A``; see
    :class:`Host`), and a host first found by that scan is flagged with a ``*``
    prefix on its address. ``discovery inspect`` shows these as-is; ``discovery
    list`` shows a subset (see
    :meth:`~mac_and_seize.modules.discovery.service.DiscoveryService.list_rows`).
    """
    ordered = sorted(hosts, key=lambda host: _ip_sort_key(host.ip))
    return [
        {
            "ip": f"*{host.ip}" if host.is_new else host.ip,
            "state": host.state,
            "mac": host.mac or "-",
            "vendor": host.vendor or "-",
            "ports": format_ports(host.ports),
        }
        for host in ordered
    ]

"""Read interface enumeration and address records via ``netifaces``.

Produces the plain address-record dicts that populate an :class:`Interface`
entity's ``ipv4``/``ipv6``/``mac`` fields (see
:func:`mac_and_seize.net.model.interface.empty_record` for the shape).
"""

from __future__ import annotations

import netifaces as ni

from mac_and_seize.net.model.interface import (
    IPV4_FIELDS,
    IPV6_FIELDS,
    MAC_FIELDS,
    empty_record,
)


def list_names() -> list[str]:
    """Return the names of all network interfaces on the host."""
    return ni.interfaces()


def _record(info_list: list[dict], fields: list[str]) -> dict:
    record = {field: [entry.get(field) for entry in info_list] for field in fields}
    record["count"] = len(info_list)
    return record


def _alias_netmask(entry: dict) -> dict:
    """netifaces reports the netmask under ``netmask``; netifaces2 uses ``mask``."""
    if "netmask" not in entry and "mask" in entry:
        entry = {**entry, "netmask": entry["mask"]}
    return entry


# On Linux, netifaces2 reports link-layer (MAC) addresses under AF_PACKET
# rather than AF_LINK (which it hardcodes to a Windows-only value).
_MAC_FAMILIES = (ni.AF_LINK, getattr(ni, "AF_PACKET", None))


def read_addresses(name: str) -> tuple[dict, dict, dict]:
    """Return ``(ipv4, ipv6, mac)`` address records for ``name``.

    Each record maps its fields (``addr``, ``netmask``, ...) to a list of
    per-address values, plus a ``count``. A family with no addresses yields the
    empty record.
    """
    addrs = ni.ifaddresses(name)

    def record(family: int, fields: list[str]) -> dict:
        info = addrs.get(family)
        if not info:
            return empty_record(fields)
        return _record([_alias_netmask(entry) for entry in info], fields)

    def mac_record(fields: list[str]) -> dict:
        info = next((addrs[fam] for fam in _MAC_FAMILIES if fam in addrs), None)
        if not info:
            return empty_record(fields)
        return _record(info, fields)

    return (
        record(ni.AF_INET, IPV4_FIELDS),
        record(ni.AF_INET6, IPV6_FIELDS),
        mac_record(MAC_FIELDS),
    )

"""The :class:`Interface` domain entity.

A **pure** data holder: it carries an interface's name, id, link state, and its
IPv4/IPv6/MAC address records, and can render itself as a plain dict. It performs
no I/O - reading state/addresses and mutating the interface are the ``ip`` /
``netifaces`` adapters' responsibility, and the application service composes them
to build and refresh instances. This keeps the domain model free of the OS.

The address records keep the shape produced by the ``netifaces`` adapter: a dict
mapping each field (``addr``, ``netmask``, ...) to a list of per-address values,
plus a ``count``. :func:`empty_record` builds the zero-address form.
"""

from __future__ import annotations

from dataclasses import dataclass, field

IPV4_FIELDS = ["addr", "netmask", "broadcast", "peer"]
IPV6_FIELDS = ["addr", "netmask", "broadcast", "peer"]
MAC_FIELDS = ["addr", "peer"]


def empty_record(fields: list[str]) -> dict:
    """An address record with no addresses (all field lists empty, count 0)."""
    record = {name: [] for name in fields}
    record["count"] = 0
    return record


@dataclass
class Interface:
    """A network interface: identity, link state, and its address records."""

    name: str
    id: int | None = None
    state: str = "unknown"
    ipv4: dict = field(default_factory=lambda: empty_record(IPV4_FIELDS))
    ipv6: dict = field(default_factory=lambda: empty_record(IPV6_FIELDS))
    mac: dict = field(default_factory=lambda: empty_record(MAC_FIELDS))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "id": self.id,
            "state": self.state,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "mac": self.mac,
        }

    def __repr__(self) -> str:
        return f"Interface(name={self.name!r}, state={self.state!r})"

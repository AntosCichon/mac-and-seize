"""Address value objects: :class:`MacAddress`, :class:`IPAddress`, :class:`CIDR`.

These are immutable, self-validating domain types. Each owns the parsing and
canonicalisation that used to be scattered across the interface module's
``_normalize_*`` helpers, so *any* module gets one authoritative notion of "a
valid MAC" / "a valid address" simply by parsing into these types. A parsed
value is guaranteed well-formed; ``str(value)`` yields its canonical form, which
adapters hand to ``ip``/scapy at the edge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
)

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")


def _require_version(version: int) -> None:
    if version not in (4, 6):
        raise ValueError(f"Invalid IP version {version!r}; expected 4 or 6.")


@dataclass(frozen=True)
class MacAddress:
    """A hardware (MAC) address in canonical lowercase colon form."""

    value: str

    @classmethod
    def parse(cls, raw: str) -> "MacAddress":
        """Validate ``raw`` and return a canonicalised :class:`MacAddress`.

        Accepts colon- or hyphen-separated hex octets; raises :class:`ValueError`
        for anything malformed.
        """
        candidate = raw.strip()
        if not _MAC_RE.match(candidate):
            raise ValueError(
                f"Invalid MAC address {raw!r}; expected 6 hex octets like "
                "'00:11:22:33:44:55'."
            )
        return cls(candidate.replace("-", ":").lower())

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class IPAddress:
    """A bare (prefix-less) IPv4/IPv6 host address - e.g. a gateway."""

    value: str
    version: int

    @classmethod
    def parse(cls, raw: str, version: int) -> "IPAddress":
        """Validate a host address of the given family (4 or 6)."""
        _require_version(version)
        factory = IPv4Address if version == 4 else IPv6Address
        try:
            addr = factory(raw.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid IPv{version} address {raw!r}: {exc}") from exc
        return cls(str(addr), version)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class CIDR:
    """An IPv4/IPv6 address *with* a prefix length - an interface address.

    A bare address without a prefix defaults to ``/32`` (IPv4) or ``/128``
    (IPv6), matching ``ip addr`` behaviour.
    """

    value: str
    version: int

    @classmethod
    def parse(cls, raw: str, version: int) -> "CIDR":
        """Validate an address/prefix of the given family and canonicalise it."""
        _require_version(version)
        factory = IPv4Interface if version == 4 else IPv6Interface
        try:
            iface = factory(raw.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid IPv{version} address {raw!r}: {exc}") from exc
        return cls(iface.with_prefixlen, version)

    def __str__(self) -> str:
        return self.value

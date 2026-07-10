"""Business operations on network interfaces (the module's service layer)."""

from __future__ import annotations

import re
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
)

from mac_and_seize.modules.interface.net import (
    Interface,
    add_ip_address,
    get_permanent_mac,
    interface_names,
    remove_ip_address,
    set_default_gateway,
    set_ip_address,
    set_link_state,
    set_mac_address,
)
from mac_and_seize.observability import get_logger

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")


def _normalize_mac(mac: str) -> str:
    """Validate and normalize a MAC address to lowercase colon form."""
    candidate = mac.strip()
    if not _MAC_RE.match(candidate):
        raise ValueError(
            f"Invalid MAC address {mac!r}; expected 6 hex octets like "
            "'00:11:22:33:44:55' (or 'default' to restore the factory MAC)."
        )
    return candidate.replace("-", ":").lower()


def _normalize_ip(address: str, version: int) -> str:
    """Validate an IPv4/IPv6 CIDR address and return its canonical form.

    A bare address without a prefix defaults to /32 (IPv4) or /128 (IPv6).
    Raises :class:`ValueError` for malformed input or a family mismatch.
    """
    factory = IPv4Interface if version == 4 else IPv6Interface
    try:
        return factory(address.strip()).with_prefixlen
    except ValueError as exc:
        raise ValueError(f"Invalid IPv{version} address {address!r}: {exc}") from exc


def _normalize_gateway(gateway: str, version: int) -> str:
    """Validate a bare (prefix-less) IPv4/IPv6 gateway address."""
    factory = IPv4Address if version == 4 else IPv6Address
    try:
        return str(factory(gateway.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IPv{version} gateway {gateway!r}: {exc}") from exc


class InterfaceService:
    """Manage and inspect network interfaces.

    Owns the interface registry (and id assignment). Safe to construct once per
    process and share between the CLI and the web interface.
    """

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._registry: dict[str, Interface] = {}
        self._next_id = 0

    def list_names(self) -> list[str]:
        return interface_names()

    def get(self, name: str) -> Interface:
        """Return a cached :class:`Interface`, creating it on first access."""
        iface = self._registry.get(name)
        if iface is None:
            iface = Interface(name, iface_id=self._next_id)
            self._next_id += 1
            self._registry[name] = iface
            self._log.info("Initialized interface %s (id=%s)", name, iface.id)
        return iface

    def inspect(self, name: str) -> dict:
        iface = self.get(name)
        iface.refresh_addresses()
        iface.state = iface.get_state()
        return iface.to_dict()

    def set_state(self, name: str, state: str) -> str:
        iface = self.get(name)
        previous = iface.get_state()
        result = iface.set_state(state)
        self._log.info(
            "Interface %s state change requested: %s -> %s (now %s)",
            name,
            previous,
            state,
            result,
        )
        return result

    def set_mac(self, name: str, mac: str) -> str:
        """Set the interface's MAC address; returns the applied address.

        Passing ``"default"`` (case-insensitive) restores the permanent
        (factory) MAC address. The interface is brought down for the change and
        its prior state is restored afterwards.
        """
        iface = self.get(name)

        if mac.strip().lower() == "default":
            permanent = get_permanent_mac(name)
            if permanent is None:
                raise ValueError(
                    f"Could not determine the factory MAC address for {name!r} "
                    "(the interface may be virtual or its driver may not expose "
                    "a permanent address)."
                )
            target = permanent
            self._log.info("Resolved factory MAC for %s: %s", name, target)
        else:
            target = _normalize_mac(mac)

        previous_state = iface.get_state()
        set_link_state(name, "down")
        try:
            set_mac_address(name, target)
        finally:
            if previous_state != "down":
                set_link_state(name, "up")

        iface.refresh_addresses()
        iface.state = iface.get_state()
        self._log.info("Set MAC of %s to %s", name, target)
        return target

    def add_ip(
        self, name: str, address: str, version: int, gateway: str | None = None
    ) -> tuple[str, str | None]:
        """Add an IPv4/IPv6 address, keeping any existing ones.

        Returns ``(applied_cidr, applied_gateway)``; ``applied_gateway`` is
        ``None`` when no gateway was requested.
        """
        iface = self.get(name)
        normalized = _normalize_ip(address, version)
        add_ip_address(name, normalized, version)
        gw = self._apply_gateway(name, gateway, version)
        iface.refresh_addresses()
        self._log.info("Added IPv%d %s to %s", version, normalized, name)
        return normalized, gw

    def remove_ip(self, name: str, address: str, version: int) -> str:
        """Remove an IPv4/IPv6 address from the interface; returns the CIDR."""
        iface = self.get(name)
        normalized = _normalize_ip(address, version)
        remove_ip_address(name, normalized, version)
        iface.refresh_addresses()
        self._log.info("Removed IPv%d %s from %s", version, normalized, name)
        return normalized

    def set_ip(
        self, name: str, address: str, version: int, gateway: str | None = None
    ) -> tuple[str, str | None]:
        """Replace the interface's IPv4/IPv6 address(es) with a single address.

        Existing addresses of the same family are flushed before the new one is
        added. Returns ``(applied_cidr, applied_gateway)``.
        """
        iface = self.get(name)
        normalized = _normalize_ip(address, version)
        set_ip_address(name, normalized, version)
        gw = self._apply_gateway(name, gateway, version)
        iface.refresh_addresses()
        self._log.info("Set IPv%d of %s to %s", version, name, normalized)
        return normalized, gw

    def _apply_gateway(
        self, name: str, gateway: str | None, version: int
    ) -> str | None:
        """Install a default gateway if one was requested; return the applied IP."""
        if not gateway:
            return None
        normalized = _normalize_gateway(gateway, version)
        set_default_gateway(name, normalized, version)
        self._log.info(
            "Set IPv%d default gateway via %s on %s", version, normalized, name
        )
        return normalized

    def list_details(self) -> list[dict]:
        return [self.inspect(name) for name in self.list_names()]

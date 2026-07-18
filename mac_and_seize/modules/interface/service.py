"""Business operations on network interfaces (the module's service layer).

An application-layer orchestrator over the shared network domain
(:mod:`mac_and_seize.net`): it parses input into value objects, composes the
``ip``/``ethtool``/``netifaces`` adapters to build and mutate
:class:`~mac_and_seize.net.model.interface.Interface` entities, and owns the
module's cross-cutting workflow (the interface registry, id assignment, and the
route-preservation sequencing for MAC/address changes).
"""

from __future__ import annotations

from dataclasses import dataclass

from mac_and_seize.net import CIDR, IPAddress, Interface, MacAddress, Route
from mac_and_seize.net.adapters import ethtool, ip, netifaces_io, wireless
from mac_and_seize.observability import get_logger


@dataclass
class MacChangeResult:
    """Outcome of :meth:`InterfaceService.set_mac`."""

    mac: str
    routes_restored: int = 0
    routes_failed: int = 0


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
        return netifaces_io.list_names()

    def _load(self, iface: Interface) -> None:
        """Refresh an entity's live link state and address records in place."""
        iface.state = ip.read_state(iface.name)
        iface.ipv4, iface.ipv6, iface.mac = netifaces_io.read_addresses(iface.name)

    def get(self, name: str) -> Interface:
        """Return a cached :class:`Interface`, creating it on first access."""
        iface = self._registry.get(name)
        if iface is None:
            if name not in netifaces_io.list_names():
                raise ValueError(f"Interface {name!r} does not exist.")
            iface = Interface(name, id=self._next_id)
            self._load(iface)
            self._next_id += 1
            self._registry[name] = iface
            self._log.info("Initialized interface %s (id=%s)", name, iface.id)
        return iface

    def inspect(self, name: str) -> dict:
        iface = self.get(name)
        self._load(iface)
        return iface.to_dict()

    def set_state(self, name: str, state: str) -> str:
        iface = self.get(name)
        if state not in ("up", "down"):
            raise ValueError(
                f"Invalid state {state!r} for interface {name!r}."
            )
        previous = ip.read_state(name)
        if previous != state:
            ip.set_link_state(name, state)
        iface.state = ip.read_state(name)
        self._log.info(
            "Interface %s state change requested: %s -> %s (now %s)",
            name,
            previous,
            state,
            iface.state,
        )
        return iface.state

    def set_mode(self, name: str, mode: str) -> str:
        """Switch a wireless interface between ``monitor`` and ``managed`` mode.

        Only valid on 802.11 interfaces; a wired or non-existent interface is
        rejected with a :class:`ValueError`. The link is briefly cycled by the
        wireless adapter to change type. Returns the applied mode.
        """
        mode = mode.strip().lower()
        if mode not in ("monitor", "managed"):
            raise ValueError(f"Invalid mode {mode!r}; expected 'monitor' or 'managed'.")
        self._require_wireless(name)
        wireless.set_mode(name, mode)
        self._log.info("Set %s to %s mode", name, mode)
        return mode

    def set_channel(self, name: str, channel: int) -> int:
        """Tune a monitor-mode wireless interface to an IEEE 802.11 ``channel``.

        Only valid on 802.11 interfaces already in monitor mode (enforced by the
        wireless adapter). Returns the applied channel number.
        """
        self._require_wireless(name)
        wireless.set_channel(name, channel)
        self._log.info("Set %s to channel %d", name, channel)
        return channel

    def _require_wireless(self, name: str) -> None:
        """Raise a clear error unless ``name`` is an existing 802.11 interface."""
        if name not in netifaces_io.list_names():
            raise ValueError(f"Interface {name!r} does not exist.")
        if not wireless.is_wireless(name):
            raise ValueError(f"{name!r} is not a wireless interface.")

    def set_mac(
        self, name: str, mac: str, *, preserve_routes: bool = True
    ) -> MacChangeResult:
        """Set the interface's MAC address; returns the outcome.

        Passing ``"default"`` (case-insensitive) restores the permanent
        (factory) MAC address. The interface is brought down for the change and
        its prior state is restored afterwards. Bringing the link down drops
        its routes (including the default gateway); by default they are
        snapshotted beforehand and restored once the interface is back up.
        Pass ``preserve_routes=False`` to skip this and leave routing to
        whatever else manages it (DHCP client, NetworkManager, ...).
        """
        iface = self.get(name)

        if mac.strip().lower() == "default":
            permanent = ethtool.get_permanent_mac(name)
            if permanent is None:
                raise ValueError(
                    f"Could not determine the factory MAC address for {name!r} "
                    "(the interface may be virtual or its driver may not expose "
                    "a permanent address)."
                )
            target = permanent
            self._log.info("Resolved factory MAC for %s: %s", name, target)
        else:
            target = MacAddress.parse(mac)

        previous_state = ip.read_state(name)
        # The link cycle drops routes for both families, so snapshot both.
        routes = (
            ip.capture_routes(name)
            if preserve_routes and previous_state != "down"
            else []
        )
        ip.set_link_state(name, "down")
        try:
            ip.set_mac_address(name, target)
        finally:
            if previous_state != "down":
                ip.set_link_state(name, "up")

        restored = failed = 0
        if routes:
            restored, failed = self._preserve(name, routes)

        self._load(iface)
        self._log.info("Set MAC of %s to %s", name, target)
        return MacChangeResult(str(target), restored, failed)

    def _preserve(self, name: str, routes: list[Route]) -> tuple[int, int]:
        """Reinstall snapshotted routes and log the outcome; return the counts.

        Thin wrapper over :func:`mac_and_seize.net.adapters.ip.restore_routes`
        (which does the actual filtering and best-effort re-application) that
        records how many routes came back.
        """
        restored, failed = ip.restore_routes(name, routes)
        if failed:
            self._log.warning(
                "Restored %d/%d route(s) on %s; %d could not be reinstalled",
                len(restored), len(routes), name, len(failed),
            )
        else:
            self._log.info("Restored %d route(s) on %s", len(restored), name)
        return len(restored), len(failed)

    def add_ip(
        self, name: str, address: str, version: int, gateway: str | None = None
    ) -> tuple[str, str | None]:
        """Add an IPv4/IPv6 address, keeping any existing ones.

        Returns ``(applied_cidr, applied_gateway)``; ``applied_gateway`` is
        ``None`` when no gateway was requested.
        """
        iface = self.get(name)
        cidr = CIDR.parse(address, version)
        ip.add_ip_address(name, cidr)
        gw = self._apply_gateway(name, gateway, version)
        self._load(iface)
        self._log.info("Added IPv%d %s to %s", version, cidr, name)
        return str(cidr), gw

    def remove_ip(self, name: str, address: str, version: int) -> str:
        """Remove an IPv4/IPv6 address from the interface; returns the CIDR."""
        iface = self.get(name)
        cidr = CIDR.parse(address, version)
        ip.remove_ip_address(name, cidr)
        self._load(iface)
        self._log.info("Removed IPv%d %s from %s", version, cidr, name)
        return str(cidr)

    def set_ip(
        self,
        name: str,
        address: str,
        version: int,
        gateway: str | None = None,
        *,
        preserve_routes: bool = True,
    ) -> tuple[str, str | None, int, int]:
        """Replace the interface's IPv4/IPv6 address(es) with a single address.

        Existing addresses of the same family are flushed before the new one is
        added. Because flushing an address also tears down the routes that
        depended on it (the default gateway, static routes), the interface's
        routes for that family are, by default, snapshotted first and re-applied
        afterwards on a best-effort basis - so connectivity is preserved when the
        new address is in the same subnet (shared with ``set_mac`` via
        :func:`mac_and_seize.net.adapters.ip.restore_routes`). Pass
        ``preserve_routes=False`` to skip this. An explicit ``gateway`` still
        wins over a restored default route. Returns
        ``(applied_cidr, applied_gateway, routes_restored, routes_failed)``.
        """
        iface = self.get(name)
        cidr = CIDR.parse(address, version)
        routes = ip.capture_routes(name, version) if preserve_routes else []
        ip.set_ip_address(name, cidr)
        restored = failed = 0
        if routes:
            restored, failed = self._preserve(name, routes)
        gw = self._apply_gateway(name, gateway, version)
        self._load(iface)
        self._log.info("Set IPv%d of %s to %s", version, name, cidr)
        return str(cidr), gw, restored, failed

    def _apply_gateway(
        self, name: str, gateway: str | None, version: int
    ) -> str | None:
        """Install a default gateway if one was requested; return the applied IP."""
        if not gateway:
            return None
        gw = IPAddress.parse(gateway, version)
        ip.set_default_gateway(name, gw)
        self._log.info(
            "Set IPv%d default gateway via %s on %s", version, gw, name
        )
        return str(gw)

    def list_details(self) -> list[dict]:
        return [self.inspect(name) for name in self.list_names()]

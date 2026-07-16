"""Low-level / privileged network operations for the interface module.

State and address *changes* go through ``ip`` via :mod:`subprocess` with an
argument list (never a shell string) - this avoids shell injection, surfaces
errors as exceptions, and is trivially mockable. Reading the permanent (factory)
MAC uses a raw ``SIOCETHTOOL`` ioctl (the same call ``ethtool -P`` makes), so no
external ``ethtool`` binary is required. Linux-specific, matching the rest of
the app.

``PrivilegedCommandError`` subclasses the shared :class:`ModuleError` so the
front-ends render it as a clean message rather than a traceback.
"""

from __future__ import annotations

import array
import fcntl
import json
import socket
import struct
import subprocess

import netifaces as ni

from mac_and_seize.core.errors import ModuleError

# ioctl / ethtool constants (from <linux/sockios.h> and <linux/ethtool.h>).
_SIOCETHTOOL = 0x8946
_ETHTOOL_GPERMADDR = 0x00000020
_MAX_ADDR_LEN = 32
_IFNAMSIZ = 16

_IPV4_FIELDS = ["addr", "netmask", "broadcast", "peer"]
_IPV6_FIELDS = ["addr", "netmask", "broadcast", "peer"]
_MAC_FIELDS = ["addr", "peer"]


class PrivilegedCommandError(ModuleError):
    """Raised when a privileged command fails or is unavailable."""


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise PrivilegedCommandError(
            f"Command not found: {cmd[0]!r}. Is it installed and on PATH?"
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() or f"exit code {exc.returncode}"
        raise PrivilegedCommandError(
            f"Command {' '.join(cmd)!r} failed: {detail}"
        ) from exc


def _family_flag(version: int) -> str:
    if version not in (4, 6):
        raise ValueError(f"Invalid IP version {version!r}; expected 4 or 6.")
    return "-4" if version == 4 else "-6"


def interface_names() -> list[str]:
    """Return the names of all network interfaces on the host."""
    return ni.interfaces()


def set_link_state(name: str, state: str) -> None:
    """Bring an interface ``up`` or ``down`` via ``ip link set``."""
    if state not in ("up", "down"):
        raise ValueError(f"Invalid state {state!r}; expected 'up' or 'down'.")
    _run(["ip", "link", "set", name, state])


def set_mac_address(name: str, mac: str) -> None:
    """Set the (running) MAC address of an interface via ``ip link set``."""
    _run(["ip", "link", "set", "dev", name, "address", mac])


def add_ip_address(name: str, address: str, version: int) -> None:
    """Add an IPv4/IPv6 address (CIDR) to an interface via ``ip addr add``."""
    _family_flag(version)  # validate version early
    _run(["ip", "addr", "add", address, "dev", name])


def remove_ip_address(name: str, address: str, version: int) -> None:
    """Remove an IPv4/IPv6 address (CIDR) from an interface via ``ip addr del``."""
    _family_flag(version)  # validate version early
    _run(["ip", "addr", "del", address, "dev", name])


def set_ip_address(name: str, address: str, version: int) -> None:
    """Replace an interface's IPv4/IPv6 address via ``ip addr``.

    Flushes the existing addresses of the given family (4 or 6), then adds the
    provided ``address`` (which must include a prefix, e.g. ``192.168.1.5/24``).
    """
    flag = _family_flag(version)
    _run(["ip", flag, "addr", "flush", "dev", name])
    _run(["ip", "addr", "add", address, "dev", name])


def set_default_gateway(name: str, gateway: str, version: int) -> None:
    """Set (replace) the default route for a family via ``ip route replace``.

    ``ip route replace`` is idempotent: it installs the default route whether or
    not one already exists, avoiding "file exists" errors on repeated calls.
    """
    flag = _family_flag(version)
    _run(["ip", flag, "route", "replace", "default", "via", gateway, "dev", name])


# --- Route preservation ---
#
# Several operations tear down an interface's routes as a side effect: changing
# the MAC cycles the link down/up, and replacing an address flushes that family.
# The default gateway and any manually-added routes do not come back on their
# own, so ``capture_routes`` snapshots them beforehand and ``restore_routes``
# best-effort reinstalls them afterward, keeping connectivity across the change.
# Both ``interface mac`` and ``interface ip4/ip6 set`` share this one mechanism.


def capture_routes(name: str, version: int | None = None) -> list[dict]:
    """Snapshot the routes attached to ``name`` for later :func:`restore_routes`.

    Parsed from ``ip -j route show`` (JSON) so restoration does not depend on
    reconstructing a command line from whitespace-sensitive text. ``version``
    limits the snapshot to one family (4 or 6); ``None`` captures both - used
    when the whole link is cycled (a MAC change), versus a single-family address
    ``set``. Each entry is the JSON object ``ip`` reported, tagged with a
    ``"family"`` key.
    """
    versions = (version,) if version is not None else (4, 6)
    entries: list[dict] = []
    for v in versions:
        result = _run(["ip", _family_flag(v), "-j", "route", "show", "dev", name])
        try:
            routes = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            # iproute2 too old for "-j"; nothing we can safely snapshot.
            continue
        for route in routes:
            route["family"] = v
            entries.append(route)
    return entries


def _is_autorecreated(route: dict) -> bool:
    """True for kernel-managed connected routes.

    The kernel recreates the connected/link route for an address on its own once
    the address is (re)assigned, so we must not try to reinstall it ourselves.
    Identified by ``protocol == "kernel"`` with no gateway.
    """
    return route.get("protocol") == "kernel" and not route.get("gateway")


def _replace_route_command(name: str, route: dict) -> list[str]:
    """Build the ``ip route replace`` command that reinstalls one captured route.

    A ``src``/``prefsrc`` clause is intentionally dropped: after an address
    change the old source may be invalid, so the kernel is left to pick one.
    """
    cmd = [
        "ip", _family_flag(route["family"]), "route", "replace",
        route.get("dst", "default"),
    ]
    if route.get("gateway"):
        cmd += ["via", route["gateway"]]
    if route.get("scope"):
        cmd += ["scope", str(route["scope"])]
    if route.get("metric") is not None:
        cmd += ["metric", str(route["metric"])]
    cmd += ["dev", name]
    return cmd


def restore_routes(name: str, routes: list[dict]) -> tuple[list[dict], list[dict]]:
    """Best-effort re-application of routes from :func:`capture_routes`.

    Kernel-managed connected routes are skipped (the kernel recreates them).
    Direct (non-gateway) routes are reinstalled before ``via`` routes, since a
    gateway route is only accepted once the on-link route that reaches the
    gateway exists. A route that can no longer be installed - e.g. its gateway is
    off-link because a new address moved the interface to another subnet - is
    skipped rather than aborting the whole operation. Returns
    ``(restored, failed)``.
    """
    restored: list[dict] = []
    failed: list[dict] = []
    for route in sorted(routes, key=lambda r: r.get("gateway") is not None):
        if _is_autorecreated(route):
            continue
        try:
            _run(_replace_route_command(name, route))
        except PrivilegedCommandError:
            failed.append(route)
            continue
        restored.append(route)
    return restored, failed


def get_permanent_mac(name: str) -> str | None:
    """Return the interface's permanent (factory) MAC via ``SIOCETHTOOL``.

    Uses the ``ETHTOOL_GPERMADDR`` ioctl (no external ``ethtool`` dependency).
    Returns ``None`` when the address cannot be determined - e.g. the driver
    does not support it (virtual interfaces) or it reports all-zeros.
    """
    if len(name.encode()) >= _IFNAMSIZ:
        raise ValueError(f"Interface name too long: {name!r}")

    # struct ethtool_perm_addr { __u32 cmd; __u32 size; __u8 data[]; }
    ecmd = array.array(
        "B",
        struct.pack("II", _ETHTOOL_GPERMADDR, _MAX_ADDR_LEN) + b"\x00" * _MAX_ADDR_LEN,
    )
    buf_addr, _ = ecmd.buffer_info()
    # struct ifreq { char ifr_name[IFNAMSIZ]; ... void *ifr_data; }
    ifreq = struct.pack(f"{_IFNAMSIZ}sP", name.encode(), buf_addr)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            fcntl.ioctl(sock.fileno(), _SIOCETHTOOL, ifreq)
        except OSError:
            # EOPNOTSUPP / ENODEV / permission, etc. - caller treats as unknown.
            return None

    size = struct.unpack("II", ecmd[:8].tobytes())[1]
    if size == 0:
        return None
    data = ecmd[8 : 8 + size].tobytes()
    mac = ":".join(f"{byte:02x}" for byte in data)
    if mac == "00:00:00:00:00:00":
        return None
    return mac


def _empty(fields: list[str]) -> dict:
    entry = {field: [] for field in fields}
    entry["count"] = 0
    return entry


class Interface:
    """The :class:`Interface` domain entity.

    Deliberately free of application concerns: it does not import the logger and
    owns no global state. It raises exceptions on failure and lets callers
    (services) decide how to log/report.
    """

    def __init__(self, name: str, iface_id: int | None = None):
        if name not in interface_names():
            raise ValueError(f"Interface {name!r} does not exist.")
        self.name = name
        self.id = iface_id
        self.system_path = f"/sys/class/net/{name}/"
        self.ipv4 = _empty(_IPV4_FIELDS)
        self.ipv6 = _empty(_IPV6_FIELDS)
        self.mac = _empty(_MAC_FIELDS)
        self.state = self.get_state()
        self.refresh_addresses()

    def get_state(self) -> str:
        with open(f"{self.system_path}operstate", "r") as f:
            return f.read().strip()

    def _gather(self, family: int, store: dict, fields: list[str], address_type=None):
        addresses = ni.ifaddresses(self.name)
        if family not in addresses:
            store["count"] = 0
            return store[address_type] if address_type is not None else store
        info = addresses[family]
        store["count"] = len(info)
        for field in [address_type] if address_type is not None else fields:
            store[field] = [info[i].get(field) for i in range(store["count"])]
        return store[address_type] if address_type is not None else store

    def get_ipv4(self, address_type=None):
        return self._gather(ni.AF_INET, self.ipv4, _IPV4_FIELDS, address_type)

    def get_ipv6(self, address_type=None):
        return self._gather(ni.AF_INET6, self.ipv6, _IPV6_FIELDS, address_type)

    def get_mac(self, address_type=None):
        return self._gather(ni.AF_LINK, self.mac, _MAC_FIELDS, address_type)

    def refresh_addresses(self) -> None:
        self.get_ipv4()
        self.get_ipv6()
        self.get_mac()

    def set_state(self, new_state: str) -> str:
        """Bring the interface ``up``/``down``; returns the resulting state."""
        if new_state not in ("up", "down"):
            raise ValueError(
                f"Invalid state {new_state!r} for interface {self.name!r}."
            )
        if self.get_state() != new_state:
            set_link_state(self.name, new_state)
        self.state = self.get_state()
        return self.state

    def up(self) -> str:
        return self.set_state("up")

    def down(self) -> str:
        return self.set_state("down")

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

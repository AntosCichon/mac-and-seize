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


# Tokens ``ip route show`` prints as status but ``ip route replace`` rejects.
_ROUTE_STATUS_FLAGS = {"linkdown", "dead"}


def get_device_routes(name: str, version: int) -> list[str]:
    """Return the routes currently attached to an interface (one spec per line).

    Output mirrors ``ip -<v> route show dev <name>`` (the ``dev <name>`` clause
    is implied and therefore omitted from each line).
    """
    flag = _family_flag(version)
    result = _run(["ip", flag, "route", "show", "dev", name])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _route_replace_args(spec: str, name: str) -> list[str] | None:
    """Convert a captured route line into ``ip route replace`` arguments.

    Returns ``None`` for kernel-managed connected routes (the kernel recreates
    those for the new address). A stale ``src <addr>`` clause is dropped so the
    kernel picks a valid source, status-only flags are removed, and ``dev`` is
    re-attached (``ip route show dev`` omits it).
    """
    tokens = spec.split()
    if "proto" in tokens:
        proto = tokens[tokens.index("proto") + 1 : tokens.index("proto") + 2]
        if proto == ["kernel"] and "via" not in tokens:
            return None

    args: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token == "src":  # drop 'src <addr>' - source may no longer be valid
            skip_next = True
            continue
        if token in _ROUTE_STATUS_FLAGS:
            continue
        args.append(token)
    if "dev" not in args:
        args += ["dev", name]
    return args


def restore_routes(name: str, version: int, routes: list[str]) -> list[str]:
    """Best-effort re-application of routes captured before an address change.

    Used by ``set`` to preserve connectivity: the default gateway and other
    routes that were valid beforehand are reinstalled after the new address is
    added. Kernel-managed connected routes are skipped (auto-recreated), and any
    route that can no longer be installed - e.g. its gateway is off-link because
    the new address is in a different subnet - is skipped instead of failing the
    whole operation. Returns the specs that were successfully restored.
    """
    flag = _family_flag(version)
    restored: list[str] = []
    for spec in routes:
        args = _route_replace_args(spec, name)
        if args is None:
            continue
        try:
            _run(["ip", flag, "route", "replace", *args])
        except PrivilegedCommandError:
            continue
        restored.append(spec)
    return restored


def set_default_gateway(name: str, gateway: str, version: int) -> None:
    """Set (replace) the default route for a family via ``ip route replace``.

    ``ip route replace`` is idempotent: it installs the default route whether or
    not one already exists, avoiding "file exists" errors on repeated calls.
    """
    flag = _family_flag(version)
    _run(["ip", flag, "route", "replace", "default", "via", gateway, "dev", name])


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

"""Interface, address, and route operations via the ``ip`` tool and sysfs.

All state *changes* go through ``ip`` with an argument list (never a shell
string): this avoids shell injection, surfaces errors as exceptions
(:class:`PrivilegedCommandError`), and is trivially mockable. Read-only link
state comes straight from sysfs. Functions accept the domain value objects
(:class:`MacAddress`, :class:`CIDR`, :class:`IPAddress`, :class:`Route`) and
serialise them to ``ip`` arguments here, at the edge - so anything reaching this
layer is already validated. Linux-specific, matching the rest of the app.
"""

from __future__ import annotations

import json

from mac_and_seize.net.adapters.privileged import (
    PrivilegedCommandError,
    family_flag,
    run,
)
from mac_and_seize.net.model.addresses import CIDR, IPAddress, MacAddress
from mac_and_seize.net.model.route import Route

# --- Link ------------------------------------------------------------------


def set_link_state(name: str, state: str) -> None:
    """Bring an interface ``up`` or ``down`` via ``ip link set``."""
    if state not in ("up", "down"):
        raise ValueError(f"Invalid state {state!r}; expected 'up' or 'down'.")
    run(["ip", "link", "set", name, state])


def set_mac_address(name: str, mac: MacAddress) -> None:
    """Set the (running) MAC address of an interface via ``ip link set``."""
    run(["ip", "link", "set", "dev", name, "address", str(mac)])


def read_state(name: str) -> str:
    """Return the interface's operational state (from sysfs ``operstate``)."""
    with open(f"/sys/class/net/{name}/operstate") as f:
        return f.read().strip()


def is_up(name: str) -> bool:
    """Whether the interface's administrative ``IFF_UP`` flag is set.

    Read from sysfs rather than by opening a socket: cheap, needs no privileges,
    and correctly reports loopback-style interfaces as up even though their
    ``operstate`` is ``"unknown"``. A vanished or unreadable interface is treated
    as down rather than raising.
    """
    try:
        with open(f"/sys/class/net/{name}/flags") as f:
            flags = int(f.read().strip(), 16)
    except (OSError, ValueError):
        return False
    return bool(flags & 0x1)  # IFF_UP


# --- Addresses -------------------------------------------------------------


def add_ip_address(name: str, address: CIDR) -> None:
    """Add an IPv4/IPv6 address to an interface via ``ip addr add``."""
    run(["ip", "addr", "add", str(address), "dev", name])


def remove_ip_address(name: str, address: CIDR) -> None:
    """Remove an IPv4/IPv6 address from an interface via ``ip addr del``."""
    run(["ip", "addr", "del", str(address), "dev", name])


def set_ip_address(name: str, address: CIDR) -> None:
    """Replace an interface's addresses of one family via ``ip addr``.

    Flushes the existing addresses of ``address``'s family, then adds it.
    """
    run(["ip", family_flag(address.version), "addr", "flush", "dev", name])
    run(["ip", "addr", "add", str(address), "dev", name])


def set_default_gateway(name: str, gateway: IPAddress) -> None:
    """Set (replace) the default route for a family via ``ip route replace``.

    ``ip route replace`` is idempotent: it installs the default route whether or
    not one already exists, avoiding "file exists" errors on repeated calls.
    """
    run([
        "ip", family_flag(gateway.version), "route", "replace",
        "default", "via", str(gateway), "dev", name,
    ])


# --- Route preservation ----------------------------------------------------
#
# Several operations tear down an interface's routes as a side effect: changing
# the MAC cycles the link down/up, and replacing an address flushes that family.
# The default gateway and any manually-added routes do not come back on their
# own, so ``capture_routes`` snapshots them beforehand and ``restore_routes``
# best-effort reinstalls them afterward, keeping connectivity across the change.


def capture_routes(name: str, version: int | None = None) -> list[Route]:
    """Snapshot the routes attached to ``name`` for later :func:`restore_routes`.

    Parsed from ``ip -j route show`` (JSON) so restoration does not depend on
    reconstructing a command line from whitespace-sensitive text. ``version``
    limits the snapshot to one family (4 or 6); ``None`` captures both - used
    when the whole link is cycled (a MAC change), versus a single-family address
    ``set``.
    """
    versions = (version,) if version is not None else (4, 6)
    routes: list[Route] = []
    for v in versions:
        result = run(["ip", family_flag(v), "-j", "route", "show", "dev", name])
        try:
            entries = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            # iproute2 too old for "-j"; nothing we can safely snapshot.
            continue
        routes.extend(Route.from_json(entry, v) for entry in entries)
    return routes


def _replace_command(name: str, route: Route) -> list[str]:
    """Build the ``ip route replace`` command that reinstalls ``route`` on ``name``.

    A ``src``/``prefsrc`` clause is intentionally dropped: after an address
    change the old source may be invalid, so the kernel is left to pick one.
    """
    cmd = ["ip", family_flag(route.family), "route", "replace", route.dst]
    if route.gateway:
        cmd += ["via", route.gateway]
    if route.scope:
        cmd += ["scope", route.scope]
    if route.metric is not None:
        cmd += ["metric", str(route.metric)]
    cmd += ["dev", name]
    return cmd


def restore_routes(name: str, routes: list[Route]) -> tuple[list[Route], list[Route]]:
    """Best-effort re-application of routes from :func:`capture_routes`.

    Kernel-managed connected routes are skipped (the kernel recreates them).
    Direct (non-gateway) routes are reinstalled before ``via`` routes, since a
    gateway route is only accepted once the on-link route that reaches the
    gateway exists. A route that can no longer be installed - e.g. its gateway is
    off-link because a new address moved the interface to another subnet - is
    skipped rather than aborting the whole operation. Returns
    ``(restored, failed)``.
    """
    restored: list[Route] = []
    failed: list[Route] = []
    for route in sorted(routes, key=lambda r: r.gateway is not None):
        if route.is_autorecreated():
            continue
        try:
            run(_replace_command(name, route))
        except PrivilegedCommandError:
            failed.append(route)
            continue
        restored.append(route)
    return restored, failed

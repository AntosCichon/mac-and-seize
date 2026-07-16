"""Actions exposed by the interface module.

Handlers are thin adapters: they fetch the module's service from the context
(``context.service("interface")``), call it, and return plain data. All the
address-changing operations require root; validation lives in the service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.interface.service import InterfaceService

# Service key this module registers under (see the package's register()).
SERVICE = "interface"

GROUP_DESCRIPTIONS = {
    "interface": "Inspect and control network interfaces",
    "interface.state": "Bring interfaces up or down",
    "interface.ip4": "Add, remove, or set IPv4 addresses",
    "interface.ip6": "Add, remove, or set IPv6 addresses",
}


def _service(context: "AppContext") -> "InterfaceService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _iface_summary(details: dict) -> dict:
    """Flatten the nested interface details into UI-friendly fields."""

    def join(entries: list) -> str:
        return ", ".join(a for a in entries if a) or "-"

    return {
        "name": details["name"],
        "state": details["state"],
        "ipv4": join(details["ipv4"]["addr"]),
        "ipv6": join(details["ipv6"]["addr"]),
        "mac": join(details["mac"]["addr"]),
    }


# --- Handlers ---


def _list_interfaces(context: "AppContext", values: dict) -> list[dict]:
    service = _service(context)
    return [_iface_summary(service.inspect(name)) for name in service.list_names()]


def _show_interface(context: "AppContext", values: dict) -> dict:
    return _iface_summary(_service(context).inspect(values["name"]))


def _interface_up(context: "AppContext", values: dict) -> str:
    state = _service(context).set_state(values["name"], "up")
    return f"{values['name']} is now {state}"


def _interface_down(context: "AppContext", values: dict) -> str:
    state = _service(context).set_state(values["name"], "down")
    return f"{values['name']} is now {state}"


def _set_mac(context: "AppContext", values: dict) -> str:
    result = _service(context).set_mac(
        values["name"], values["mac"], preserve_routes=not values["no-preserve"]
    )
    label = "MAC reset to factory default" if values["mac"].strip().lower() == "default" \
        else "MAC set to"
    message = f"{values['name']} {label} {result.mac}"
    if result.routes_restored or result.routes_failed:
        detail = f"{result.routes_restored} route(s) restored"
        if result.routes_failed:
            detail += f", {result.routes_failed} failed - see logs"
        message += f" [{detail}]"
    return message


def _make_ip_handler(operation: str, version: int) -> Callable[["AppContext", dict], str]:
    """Build a handler for one (operation, IP version) combination."""

    def handler(context: "AppContext", values: dict) -> str:
        service = _service(context)
        name = values["name"]
        address = values["address"]
        if operation == "remove":
            applied = service.remove_ip(name, address, version)
            return f"{name}: removed IPv{version} address {applied}"

        gateway = values.get("gateway")
        if operation == "set":
            applied, gw, restored, failed = service.set_ip(
                name, address, version, gateway,
                preserve_routes=not values.get("no-preserve", False),
            )
            message = f"{name}: IPv{version} set to {applied}"
        else:  # add
            applied, gw = service.add_ip(name, address, version, gateway)
            restored = failed = 0
            message = f"{name}: added IPv{version} address {applied}"
        if gw:
            message += f", default gateway {gw}"
        if restored or failed:
            detail = f"{restored} route(s) restored"
            if failed:
                detail += f", {failed} failed - see logs"
            message += f" [{detail}]"
        return message

    return handler


def _ip_actions() -> list[Action]:
    """Build the ip4/ip6 add|remove|set actions (each requires root)."""
    actions: list[Action] = []
    for version in (4, 6):
        fam = f"ip{version}"
        example_addr = "192.168.1.50/24" if version == 4 else "2001:db8::10/64"
        example_gw = "192.168.1.1" if version == 4 else "2001:db8::1"

        name_param = Param("name", "Interface name (e.g. eth0)", multiple=True)
        addr_list = Param(
            "address", f"IPv{version} address in CIDR (e.g. {example_addr})",
            multiple=True,
        )
        addr_one = Param("address", f"IPv{version} address in CIDR (e.g. {example_addr})")
        gw_param = Param(
            "gateway",
            f"Also set the default gateway (e.g. {example_gw})",
            str,
            required=False,
        )
        no_preserve_param = Param(
            "no-preserve",
            "Skip restoring routes dropped when the address is flushed",
            bool,
            required=False,
            default=False,
            is_flag=True,
        )

        actions.append(Action(
            f"interface.{fam}.add",
            f"Add IPv{version} address",
            f"Add an IPv{version} address to the interface, keeping any existing "
            "addresses (requires root).",
            _make_ip_handler("add", version),
            [name_param, addr_list, gw_param],
            [
                f"interface {fam} add eth0 {example_addr}",
                f"interface {fam} add eth0 {example_addr} --gateway {example_gw}",
            ],
            requires_root=True,
        ))
        actions.append(Action(
            f"interface.{fam}.remove",
            f"Remove IPv{version} address",
            f"Remove an IPv{version} address from the interface (requires root).",
            _make_ip_handler("remove", version),
            [name_param, addr_list],
            [f"interface {fam} remove eth0 {example_addr}"],
            requires_root=True,
        ))
        actions.append(Action(
            f"interface.{fam}.set",
            f"Set IPv{version} address",
            f"Replace the interface's IPv{version} address(es) with a single "
            "address (requires root). Flushing the old address drops the routes "
            "that depended on it (the default gateway, static routes); they are "
            "restored automatically unless --no-preserve is given.",
            _make_ip_handler("set", version),
            [name_param, addr_one, gw_param, no_preserve_param],
            [
                f"interface {fam} set eth0 {example_addr}",
                f"interface {fam} set eth0 {example_addr} --gateway {example_gw}",
                f"interface {fam} set eth0 {example_addr} --no-preserve",
            ],
            requires_root=True,
        ))
    return actions


def build_actions() -> list[Action]:
    """Return the ordered list of actions this module exposes."""
    actions: list[Action] = [
        Action(
            "interface.list",
            "List interfaces",
            "Show every interface with its state and addresses.",
            _list_interfaces,
        ),
        Action(
            "interface.show",
            "Show interface",
            "Show detailed information for a single interface.",
            _show_interface,
            [Param("name", "Interface name (e.g. eth0)", multiple=True)],
            ["interface show eth0", "interface show eth0,eth1"],
        ),
        Action(
            "interface.state.up",
            "Bring interface up",
            "Enable an interface (requires root).",
            _interface_up,
            [Param("name", "Interface name (e.g. eth0)", multiple=True)],
            ["interface state up eth0", "interface state up eth0,eth1"],
            requires_root=True,
        ),
        Action(
            "interface.state.down",
            "Bring interface down",
            "Disable an interface (requires root).",
            _interface_down,
            [Param("name", "Interface name (e.g. eth0)", multiple=True)],
            ["interface state down eth0", "interface state down eth0,eth1"],
            requires_root=True,
        ),
        Action(
            "interface.mac",
            "Set MAC address",
            "Set a MAC address, or 'default' to restore the factory MAC "
            "(requires root). The change requires briefly cycling the link, "
            "which drops its routes (including the default gateway); they are "
            "restored automatically unless --no-preserve is given. Note: on a "
            "virtualized NIC (e.g. WSL2/Hyper-V), the underlying virtual "
            "switch may still reject traffic from a non-original MAC even "
            "though routing stays intact - that is a host-side setting, not "
            "something this tool controls.",
            _set_mac,
            [
                Param("name", "Interface name (e.g. eth0)", multiple=True),
                Param("mac", "New MAC (00:11:22:33:44:55) or 'default'"),
                Param(
                    "no-preserve",
                    "Skip restoring routes dropped by the link cycle",
                    bool,
                    required=False,
                    default=False,
                    is_flag=True,
                ),
            ],
            [
                "interface mac eth0 02:11:22:33:44:55",
                "interface mac eth0 default",
                "interface mac eth0 02:11:22:33:44:55 --no-preserve",
            ],
            requires_root=True,
        ),
    ]
    actions.extend(_ip_actions())
    return actions

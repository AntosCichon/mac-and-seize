"""Actions for the ``lan dhcp`` command group (pool starvation + rogue server).

Three groups of commands, all root-only: ``find`` locates the legitimate server,
``starve`` drains and holds its address pool, and ``server`` hands those
addresses back out with settings of our choosing. Handlers stay thin - they
translate parsed values into calls on the session-scoped
:class:`~mac_and_seize.modules.lan.dhcp.service.DhcpService`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param
from mac_and_seize.core.presenter import Column

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.lan.dhcp.service import DhcpService

SERVICE = "lan_dhcp"

GROUP_DESCRIPTIONS = {
    "lan.dhcp": "DHCP automations (pool starvation and rogue server)",
    "lan.dhcp.starve": "Drain and hold a DHCP server address pool",
    "lan.dhcp.server": "Serve the starved pool as a rogue DHCP server",
}

# Column layout for the `lan dhcp starve list` table. Addresses and MACs are
# fixed-width, so nothing flexes; the row's colour comes from the state it
# already states in text (see modules/lan/dhcp/pool.py).
_POOL_COLUMNS = [
    Column("ip", "ip", 17),
    Column("state", "state", 8),
    Column("lease left", "lease left", 12),
    Column("holder", "holder", 18),
    Column("holder left", "holder left", 12),
    Column("last try", "last try", 10),
]


def _service(context: "AppContext") -> "DhcpService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _find(context: "AppContext", values: dict) -> list[dict]:
    return _service(context).find(
        context, values["interface"], timeout=values.get("timeout")
    )


def _starve_start(context: "AppContext", values: dict) -> str:
    return _service(context).starve_start(
        context, values["interface"], limit=values.get("limit")
    )


def _starve_list(context: "AppContext", values: dict) -> dict:
    rows, info = _service(context).starve_view(values.get("interface"))
    context.presenter.table(rows, _POOL_COLUMNS, title="DHCP pool")
    return info


def _starve_stop(context: "AppContext", values: dict) -> str:
    return _service(context).starve_stop(release=values.get("release"))


def _server_start(context: "AppContext", values: dict) -> str:
    return _service(context).server_start(
        context,
        values["interface"],
        values["gateway"],
        values["dns"],
        domain=values.get("domain"),
        ntp=values.get("ntp"),
        relay=bool(values.get("relay")),
        nat_relay=bool(values.get("nat-relay")),
    )


def _server_stop(context: "AppContext", values: dict) -> str:
    return _service(context).server_stop()


def build_actions() -> list[Action]:
    return [
        Action(
            "lan.dhcp.find",
            "Find the DHCP server",
            "Send a single DHCPDISCOVER on <interface> and report every server "
            "that answers, with the settings it hands out: its address and MAC, "
            "the address it offered, subnet mask, gateway, DNS, domain, NTP and "
            "lease time (requires root). More than one row means more than one "
            "server is answering on the segment - worth knowing before starving "
            "it, since draining one pool does not stop the other. This claims "
            "nothing: the offers are never accepted, so each server holds its "
            "address briefly and then puts it back. Unlike the starve and "
            "server commands this blocks until --timeout elapses (default 5s) "
            "rather than running in the background - it is a short probe, and "
            "a late second answer is exactly what it is looking for.",
            _find,
            [
                Param("interface", "Interface to probe from (e.g. eth0)"),
                Param(
                    "timeout",
                    "Seconds to listen for offers (default: 5)",
                    float,
                    required=False,
                ),
            ],
            ["lan dhcp find eth0", "lan dhcp find eth0 --timeout 10"],
            requires_root=True,
        ),
        Action(
            "lan.dhcp.starve.start",
            "Starve the DHCP pool",
            "Start a background job that leases every address the DHCP server "
            "on <interface> will hand out, each under its own forged MAC, until "
            "the pool is drained (requires root). Addresses are then *held*: "
            "each lease is renewed at T1 (half the lease) exactly as a real "
            "client would, because an expired lease goes straight back into the "
            "server pool for any real host to take. Addresses that could not "
            "be obtained - outside the server range, or already in use - are "
            "re-probed periodically by name, so a host powering off eventually "
            "hands us its address. --limit caps how many addresses to hold, "
            "which is the safe way to try this on a segment you do not want to "
            "take down entirely. The prompt stays usable; watch progress with "
            "'lan dhcp starve list' and stop with 'lan dhcp starve stop'. "
            "WARNING: this is a denial of service on the whole segment. Every "
            "client that tries to get an address while it runs will fail, "
            "including this host - if its own lease expires mid-run it loses "
            "network on that interface. For authorized security testing only.",
            _starve_start,
            [
                Param("interface", "Interface to starve the pool on (e.g. eth0)"),
                Param(
                    "limit",
                    "Stop after holding this many addresses (default: no limit)",
                    int,
                    required=False,
                ),
            ],
            [
                "lan dhcp starve start eth0",
                "lan dhcp starve start eth0 --limit 20",
            ],
            requires_root=True,
        ),
        Action(
            "lan.dhcp.starve.list",
            "List the starved pool",
            "Open a scrollable table of every address in the subnet and what we "
            "know about it, then print the subnet-wide settings the real server "
            "hands out (gateway, DNS, NTP, domain). Each address is in one of "
            "three states, shown in the 'state' column and coloured to match: "
            "'free' (grey) - we hold the lease and nothing is using it, with "
            "the time left on it; 'taken' (red) - we could not get it, with how "
            "long ago we last tried; 'leased' (green) - we hold it and the "
            "rogue server has handed it to a client, with the time left and "
            "that client MAC. Expired leases are reaped when you run this, so "
            "a pool left to age after 'starve stop' reports what is still "
            "genuinely held. Navigate with the arrow keys; press Esc, Enter or "
            "q to exit. --interface picks the pool when more than one exists.",
            _starve_list,
            [
                Param(
                    "interface",
                    "Which pool to list (default: the only one)",
                    required=False,
                ),
            ],
            ["lan dhcp starve list", "lan dhcp starve list --interface eth0"],
            requires_root=True,
        ),
        Action(
            "lan.dhcp.starve.stop",
            "Stop starving",
            "Stop every running starve job (requires root). Without --release "
            "nothing is handed back: the addresses simply stop being renewed "
            "and drain away as each lease reaches its own expiry, so they "
            "return at the server pace rather than in one visible burst, and "
            "the pool stays listable while it empties. --release free hands "
            "back only the idle ('free') addresses and keeps the ones a client "
            "is currently using; --release all hands back everything, stops the "
            "rogue server if one is running, and discards the pool. Note that "
            "DHCP does not acknowledge a release, so a release reports what was "
            "sent, not what the server did with it.",
            _starve_stop,
            [
                Param(
                    "release",
                    "Hand addresses back: 'free' (idle only) or 'all'",
                    required=False,
                ),
            ],
            [
                "lan dhcp starve stop",
                "lan dhcp starve stop --release free",
                "lan dhcp starve stop --release all",
            ],
            requires_root=True,
        ),
        Action(
            "lan.dhcp.server.start",
            "Start a rogue DHCP server",
            "Answer DHCP clients on <interface> from the addresses the starve "
            "is holding, handing out <gateway> and <dns> instead of the real "
            "server ones (requires root). This is the half that turns a starve "
            "from a denial of service into a redirection: point <gateway> at a "
            "host you control and every client that renews routes through it. "
            "Both <gateway> and <dns> are required and both accept two "
            "keywords: 'default' reuses whatever the real server hands out "
            "(which the starve has already learned - check 'lan dhcp starve "
            "list'), and 'self' expands to the own IPv4 of <interface> (convenient "
            "for the relay case and for pointing clients at services running "
            "on this box). <dns> also takes a comma-separated list; 'self' "
            "works inside a list too ('self,1.1.1.1'). --domain accepts "
            "'default' (it is text, not an address, so 'self' does not "
            "apply); --ntp accepts 'default', 'self', and comma lists like "
            "<dns>. Leases are offered from the idle ('free') addresses "
            "only, and never for longer than we hold the address ourselves, "
            "so a client is never promised time we cannot back. The server "
            "identifies itself as the own IP address of the interface, which is "
            "where clients will send their renewals. Stop it with 'lan dhcp "
            "server stop'.\n\n"
            "The rogue lease points victims at us as their gateway, so their "
            "uplink traffic arrives at our NIC destined for the real upstream "
            "router. With no relay flag this is a full uplink DoS on the "
            "victims (traffic reaches us and is discarded); pair with "
            "--relay or --nat-relay to actually intercept it. The two are "
            "mutually exclusive and both require: (a) the starve has "
            "observed the real upstream gateway (via a prior 'lan dhcp find' "
            "or an already-running 'lan dhcp starve'), and (b) <gateway> "
            "resolves to the own IP of <interface> (use 'self') - otherwise "
            "clients route to somewhere that is not us and the relay never "
            "sees a frame. The pre-flight rejects the mismatch cleanly.\n\n"
            "--relay (Python bridge): a scapy worker sniffs uplink frames "
            "arriving at our MAC, rewrites the L2 destination to the real "
            "upstream router MAC, and reinjects them on the same link. "
            "Only local, session-scoped state is touched - a dedicated "
            "nftables INPUT-drop table (mas_relay) that stops the kernel "
            "from double-processing what scapy is handling; both are torn "
            "down on 'dhcp server stop'. This is ONE-WAY MiTM: the real "
            "router replies straight to the real MAC of the victim and bypasses "
            "us. For a full two-way MiTM in this mode, layer 'lan arp spoof "
            "<victim_ip> <our_mac> --target <real_gw> --relay' alongside. "
            "Throughput is Python-limited (tens of kpps at best) but there "
            "is nothing to leave behind on abnormal termination - the "
            "leftover nftables table is inert and auto-cleaned at next "
            "launch.\n\n"
            "--nat-relay (kernel NAT): enables net.ipv4.ip_forward, forces "
            "net.ipv4.conf.<iface>.send_redirects=0, and installs a dedicated "
            "nftables NAT table (mas_relay_nat) that masquerades outgoing "
            "traffic sourced from the served leases. The kernel forwards at "
            "line rate and conntrack un-NATs the return path, so this is "
            "TWO-WAY MiTM out of the box. Impact on the running system: "
            "three snapshot-and-restore surfaces (two sysctls + the NAT "
            "table), all reverted on 'dhcp server stop'. On SIGKILL the "
            "tool self-heals the nftables tables at next launch but the "
            "sysctls stay in the state they were forced to - do NOT use on "
            "a multi-homed or production-adjacent host without verifying "
            "that forwarding will not affect other interfaces, and do NOT "
            "use on a segment whose real gateway also masquerades (double-"
            "NAT will silently break sessions). "
            "For authorized security testing only.",
            _server_start,
            [
                Param("interface", "Interface to serve on (e.g. eth0)"),
                Param(
                    "gateway",
                    "Default gateway to hand out, or 'default' for the real one",
                ),
                Param(
                    "dns",
                    "DNS server(s) to hand out (comma-separated), or 'default'",
                ),
                Param(
                    "domain",
                    "Domain name to hand out, or 'default'",
                    required=False,
                ),
                Param(
                    "ntp",
                    "NTP server(s) to hand out (comma-separated), or 'default'",
                    required=False,
                ),
                Param(
                    "relay",
                    "One-way MiTM via Python bridge (scapy)",
                    bool,
                    required=False,
                    default=False,
                    is_flag=True,
                ),
                Param(
                    "nat-relay",
                    "Two-way MiTM via kernel NAT (nftables MASQUERADE)",
                    bool,
                    required=False,
                    default=False,
                    is_flag=True,
                ),
            ],
            [
                "lan dhcp server start eth0 192.168.1.66 192.168.1.66",
                "lan dhcp server start eth0 192.168.1.66 1.1.1.1,8.8.8.8",
                "lan dhcp server start eth0 default default",
                "lan dhcp server start eth0 self self",
                "lan dhcp server start eth0 self self,1.1.1.1",
                "lan dhcp server start eth0 192.168.1.66 default --domain default --ntp self",
                "lan dhcp server start eth0 self default --relay",
                "lan dhcp server start eth0 self default --nat-relay",
            ],
            requires_root=True,
        ),
        Action(
            "lan.dhcp.server.stop",
            "Stop the rogue DHCP server",
            "Stop every running rogue DHCP server and return the addresses it "
            "handed out to the idle pool, so they can be offered again "
            "(requires root). Clients keep using their addresses until their "
            "own leases expire - nothing is taken back from them, and our "
            "leases with the real server are untouched, so the starve (if still "
            "running) goes on holding everything.",
            _server_stop,
            [],
            ["lan dhcp server stop"],
            requires_root=True,
        ),
    ]

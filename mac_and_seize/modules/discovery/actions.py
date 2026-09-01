"""Actions exposed by the discovery module - scapy-based host and port discovery.

The module keeps a single, host-oriented store, so the commands are flat under
``discovery`` (no host/service subgroups):

* ``scan`` - find live hosts with an ARP sweep;
* ``tcp`` / ``udp`` - find open ports and attach them to their host;
* ``import`` - identify active hosts from a pcap;
* ``inspect`` - open a scrollable table of discovered hosts (with their ports);
* ``list`` / ``clear`` / ``summary`` - view or reset the store;
* ``cancel`` - stop whichever scan(s) are running.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param
from mac_and_seize.core.presenter import Column

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.discovery.service import DiscoveryService

SERVICE = "discovery"

GROUP_DESCRIPTIONS = {
    "discovery": "Discover live hosts and their open ports/services",
}

# Column layout for the interactive `discovery inspect` table; the free-text
# columns (vendor, ports) flex to fill the terminal. The ip column is a touch
# wider than an address to fit the leading `*` a newly-found host carries.
_INSPECT_COLUMNS = [
    Column("ip", "ip", 17),
    Column("state", "state", 6),
    Column("mac", "mac", 18),
    Column("vendor", "vendor", 16, flex=True),
    Column("ports", "ports", 30, flex=True),
]


def _service(context: "AppContext") -> "DiscoveryService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _scan(context: "AppContext", values: dict) -> str:
    return _service(context).start_scan(
        context, values["target"], timeout=values.get("timeout")
    )


def _tcp(context: "AppContext", values: dict) -> str:
    return _service(context).start_service_scan(
        context, values["target"], "tcp",
        port=values.get("port"), timeout=values.get("timeout"),
    )


def _udp(context: "AppContext", values: dict) -> str:
    return _service(context).start_service_scan(
        context, values["target"], "udp",
        port=values.get("port"), timeout=values.get("timeout"),
    )


def _import(context: "AppContext", values: dict) -> str:
    count = _service(context).import_hosts(values["format"], values["filename"])
    return f"Identified {count} active host(s) from the capture."


def _inspect(context: "AppContext", values: dict):
    rows = _service(context).inspect_rows()
    if not rows:
        return "No hosts discovered yet; run 'discovery scan <target>' first."
    context.presenter.table(rows, _INSPECT_COLUMNS, title="Discovered hosts")
    return None


def _list(context: "AppContext", values: dict):
    rows = _service(context).list_rows()
    if not rows:
        return "No hosts discovered yet; run 'discovery scan <target>' first."
    return rows


def _clear(context: "AppContext", values: dict) -> str:
    cleared = _service(context).clear()
    return f"Cleared {cleared} discovered host(s)."


def _summary(context: "AppContext", values: dict) -> dict:
    return _service(context).summary()


def _cancel(context: "AppContext", values: dict) -> str:
    return _service(context).cancel()


def build_actions() -> list[Action]:
    return [
        Action(
            "discovery.scan",
            "Scan for hosts",
            "Start a background host-discovery sweep (a pure-scapy ARP sweep - no "
            "external nmap binary) against a target: a single IP, CIDR "
            "(192.168.1.0/24), last-octet range (192.168.1.10-20), hostname, "
            "the name of a local interface (e.g. eth0) to scan the subnet that "
            "NIC is on, or the keyword 'discovered' to re-probe every host found "
            "so far (a quick liveness recheck). For a CIDR the network and "
            "broadcast addresses are skipped. ARP is not routed, so only hosts on "
            "the local link are found. The 'state' column of each host reflects the "
            "most recent scan - up (replied), down (in range but silent), or N/A "
            "(outside the range of this scan) - and a host first seen by the latest "
            "scan is marked with a '*' before its address. The prompt stays usable "
            "while it runs and a line announces completion regardless of your "
            "current context; results appear in 'discovery list' and 'discovery "
            "inspect'. Cancelling is instant ('discovery cancel'). The sweep "
            "mirrors the -PR host discovery of nmap (requires root).",
            _scan,
            [
                Param(
                    "target",
                    "Scan target: IP, CIDR, last-octet range, hostname, a local "
                    "interface name (scans the subnet of that NIC), or 'discovered'",
                ),
                Param(
                    "timeout",
                    "Seconds to wait for ARP replies (default: 1)",
                    float,
                    required=False,
                ),
            ],
            [
                "discovery scan 192.168.1.0/24",
                "discovery scan 192.168.1.10-20",
                "discovery scan 192.168.1.1 --timeout 2",
                "discovery scan eth0",
                "discovery scan discovered",
            ],
            requires_root=True,
        ),
        Action(
            "discovery.tcp",
            "TCP SYN port scan",
            "Start a background TCP SYN scan (half-open - the handshake is never "
            "completed, mirroring the -sS mode of nmap) for open ports on a target: a single "
            "IP, CIDR, last-octet range, hostname, a local interface name (scans "
            "the subnet of that NIC), or the keyword 'discovered' to scan every host "
            "found so far. Unlike an ARP host sweep this is routed, so it reaches "
            "hosts beyond the local link. --port takes a single port, a list "
            "(22,80,443), or a range (default 1-1000). Open ports are attached to "
            "their host - see them in 'discovery list' / 'discovery inspect'; a "
            "port found on a not-yet-known IP adds that host. The prompt stays "
            "usable while it runs; cancelling is instant ('discovery cancel', "
            "requires root).",
            _tcp,
            [
                Param(
                    "target",
                    "Scan target: IP, CIDR, range, hostname, local interface name, "
                    "or 'discovered'",
                ),
                Param(
                    "port",
                    "Port(s): single, list (22,80,443), or range (default 1-1000)",
                    required=False,
                ),
                Param(
                    "timeout",
                    "Seconds to wait for replies per host (default: 2)",
                    float,
                    required=False,
                ),
            ],
            [
                "discovery tcp 192.168.1.10",
                "discovery tcp 192.168.1.0/24 --port 22,80,443",
                "discovery tcp 192.168.1.10 --port 1-65535",
                "discovery tcp discovered --port 1-1000",
            ],
            requires_root=True,
        ),
        Action(
            "discovery.udp",
            "UDP port scan",
            "Start a background UDP scan for open ports on a target (same target "
            "forms as 'discovery tcp', including 'discovered'). A closed UDP port "
            "answers with an ICMP port-unreachable; an open one usually stays "
            "silent, so a port that never replies is recorded as 'open|filtered' "
            "(open or firewalled - cannot tell apart; shown with a trailing '?' in "
            "the ports column). --port takes a single port, a list, or a range "
            "(default 1-1000). Note UDP scanning is slow and less certain than "
            "TCP: the kernel rate-limits ICMP errors, so scanning many ports "
            "quickly can leave some looking open|filtered. Cancelling is instant "
            "('discovery cancel', requires root).",
            _udp,
            [
                Param(
                    "target",
                    "Scan target: IP, CIDR, range, hostname, local interface name, "
                    "or 'discovered'",
                ),
                Param(
                    "port",
                    "Port(s): single, list (53,123,161), or range (default 1-1000)",
                    required=False,
                ),
                Param(
                    "timeout",
                    "Seconds to wait for replies per host (default: 2)",
                    float,
                    required=False,
                ),
            ],
            [
                "discovery udp 192.168.1.10 --port 53,123,161",
                "discovery udp 192.168.1.1 --port 1-1024",
                "discovery udp discovered --port 53,161",
            ],
            requires_root=True,
        ),
        Action(
            "discovery.import",
            "Import hosts from a capture",
            "Read a packet capture and identify the active hosts in it: every "
            "host that sent a packet is recorded as up, with its MAC where the "
            "capture reveals one (ARP bindings preferred, best-effort layer-2 "
            "source otherwise). Only the 'pcap' format is supported. Turns a "
            "'capture export' into a host list without sending a single probe, "
            "so unlike scanning it needs no root. Syntax mirrors 'capture "
            "import': import <format> <filename>.",
            _import,
            [
                Param("format", "Input format (only 'pcap')"),
                Param("filename", "Source .pcap file path"),
            ],
            ["discovery import pcap exports/session.pcap"],
        ),
        Action(
            "discovery.inspect",
            "Inspect discovered hosts",
            "Open a scrollable, read-only table of discovered hosts (ip, state, "
            "mac, vendor, and its open ports). 'state' is liveness versus the "
            "most recent scan - up/down/N/A - and a '*' before an address marks a "
            "host that scan found for the first time. Navigate with the arrow "
            "keys; press Esc, Enter or q to exit.",
            _inspect,
            examples=["discovery inspect"],
        ),
        Action(
            "discovery.list",
            "List discovered hosts",
            "List hosts discovered so far this session, one row per host (ip, "
            "state, mac, and its open ports as a 'port/proto' list - a trailing "
            "'?' marks a UDP open|filtered port). 'state' is liveness versus the "
            "most recent scan (up/down/N/A) and a '*' before an address marks a "
            "host that scan first found.",
            _list,
            examples=["discovery list"],
        ),
        Action(
            "discovery.clear",
            "Clear discovered hosts",
            "Discard everything discovered so far this session (hosts and their "
            "ports).",
            _clear,
            examples=["discovery clear"],
        ),
        Action(
            "discovery.summary",
            "Discovery summary",
            "Show a summary of the discovery store: host count, how many resolved "
            "a MAC/vendor, total open ports and how many hosts have them, a "
            "breakdown by discovery method, and whether a host scan or a port scan "
            "is currently running.",
            _summary,
            examples=["discovery summary"],
        ),
        Action(
            "discovery.cancel",
            "Cancel running scan(s)",
            "Cancel whichever discovery scans are running - a host scan, a port "
            "scan, or both (they run independently). This is instant: a new scan "
            "can start immediately, and the probe of each cancelled scan finishes on "
            "its own in the background with its results discarded (requires root).",
            _cancel,
            examples=["discovery cancel"],
            requires_root=True,
        ),
    ]

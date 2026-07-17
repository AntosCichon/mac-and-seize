"""Actions exposed by the discovery module - scapy-based host discovery.

Commands: `discovery host scan/cancel/import/list/clear/summary`. Service
(port/version) discovery is a stub for now: `discovery service scan` reports
that it isn't implemented.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param
from mac_and_seize.modules.discovery.host import METHODS

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.discovery.service import DiscoveryService

SERVICE = "discovery"

GROUP_DESCRIPTIONS = {
    "discovery": "Discover hosts (and, in future, services) on the network",
    "discovery.host": "Find live hosts with ARP/ICMP sweeps",
    "discovery.service": "Discover services on a host (not implemented yet)",
}


def _service(context: "AppContext") -> "DiscoveryService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _scan(context: "AppContext", values: dict) -> str:
    return _service(context).start_scan(
        context,
        values["target"],
        method=values.get("method") or "all",
        timeout=values.get("timeout"),
    )


def _cancel(context: "AppContext", values: dict) -> str:
    return _service(context).cancel_scan()


def _import(context: "AppContext", values: dict) -> str:
    count = _service(context).import_hosts(values["format"], values["filename"])
    return f"Identified {count} active host(s) from the capture."


def _list(context: "AppContext", values: dict):
    hosts = _service(context).list_hosts()
    if not hosts:
        return "No hosts discovered yet; run 'discovery host scan <target>' first."
    return hosts


def _clear(context: "AppContext", values: dict) -> str:
    cleared = _service(context).clear()
    return f"Cleared {cleared} discovered host(s)."


def _summary(context: "AppContext", values: dict) -> dict:
    return _service(context).summary()


def _service_scan(context: "AppContext", values: dict) -> None:
    _service(context).scan_services(values["ip"])


def build_actions() -> list[Action]:
    return [
        Action(
            "discovery.host.scan",
            "Scan for hosts",
            "Start a background host-discovery sweep (ARP and/or ICMP echo, in "
            "pure scapy - no external nmap binary) against a target: a single "
            "IP, CIDR (192.168.1.0/24), last-octet range (192.168.1.10-20), "
            "hostname, or the name of a local interface (e.g. eth0) to scan the "
            "subnet that NIC is on. For a CIDR the network and broadcast "
            "addresses are skipped. The prompt stays usable while it runs and a "
            "line announces completion regardless of your current context; "
            "results appear in 'discovery host list'. Cancelling is instant - "
            "you can start another scan right away - and discards the cancelled "
            "scan's results while its probe drains in the background. Method "
            "names mirror nmap's -PR/-PE options (requires root).",
            _scan,
            [
                Param(
                    "target",
                    "Scan target: IP, CIDR, last-octet range, hostname, or a "
                    "local interface name (scans that NIC's subnet)",
                ),
                Param(
                    "method",
                    f"Probe method: {', '.join(METHODS)} (arp=local subnet, "
                    "ping=ICMP echo, all=try each and stop at the first that "
                    "finds a host up)",
                    required=False,
                    default="all",
                ),
                Param(
                    "timeout",
                    "Seconds to wait for replies per sweep (default: 3)",
                    int,
                    required=False,
                ),
            ],
            [
                "discovery host scan 192.168.1.0/24",
                "discovery host scan 192.168.1.10-20 --method arp",
                "discovery host scan 192.168.1.1 --method ping --timeout 5",
                "discovery host scan eth0",
            ],
            requires_root=True,
        ),
        Action(
            "discovery.host.cancel",
            "Cancel scan",
            "Cancel the running host-discovery scan (requires root). This is "
            "instant: a new scan can start immediately, and the cancelled "
            "scan's probe finishes on its own in the background with its results "
            "discarded rather than added to the session.",
            _cancel,
            examples=["discovery host cancel"],
            requires_root=True,
        ),
        Action(
            "discovery.host.import",
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
            ["discovery host import pcap exports/session.pcap"],
        ),
        Action(
            "discovery.host.list",
            "List discovered hosts",
            "List hosts discovered so far this session (ip, mac, vendor, and "
            "the method that found each).",
            _list,
            examples=["discovery host list"],
        ),
        Action(
            "discovery.host.clear",
            "Clear discovered hosts",
            "Discard all hosts discovered so far this session.",
            _clear,
            examples=["discovery host clear"],
        ),
        Action(
            "discovery.host.summary",
            "Discovery summary",
            "Show a summary of discovered hosts: counts, how many resolved a "
            "MAC/vendor, breakdown by method, and whether a scan is "
            "currently running.",
            _summary,
            examples=["discovery host summary"],
        ),
        Action(
            "discovery.service.scan",
            "Scan services on a host",
            "Not implemented yet: service/port discovery for a single host.",
            _service_scan,
            [Param("ip", "Target host IP")],
            ["discovery service scan 192.168.1.10"],
        ),
    ]

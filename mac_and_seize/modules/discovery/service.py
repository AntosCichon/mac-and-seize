"""Discover live hosts on the network (the discovery module's session service).

Like ``CaptureService``, this is instantiated once per
:class:`~mac_and_seize.core.context.AppContext` and holds session state: hosts
found so far, keyed by IP so repeat scans refresh an already-known host
instead of duplicating it. A scan runs ARP and/or ICMP probes (via the shared
scapy adapter - no external ``nmap`` binary) in a background thread so the
prompt stays responsive; only one scan may run at a time.

A scan target is either an **address spec** (IP, CIDR, last-octet range, or
hostname) scanned via the default route, or the name of a **local interface**,
in which case the subnet that NIC is on is scanned and the probes are pinned to
that interface (so multi-homed hosts can scan the right link). See
:meth:`_resolve_target`.

The scan probes are a pure-scapy implementation whose *method selection* is
inspired by nmap's host-discovery options (ARP ``-PR`` / ICMP-echo ``-PE``);
none of nmap's code is used. The whole target is swept in one batch per method:
for ``--method all`` the ARP sweep runs first and the ICMP sweep then probes
only the hosts ARP did not already find up (so no host is probed twice).

scapy's ``sr``/``srp`` block until their timeout with no cooperative interrupt
point, so a running probe cannot be stopped mid-flight. ``cancel_scan`` is
therefore *instant by detachment* (see ``modules/README.md`` §9): each scan is a
:class:`_Run` with its own identity, and cancelling drops its task from
``tasks``, clears it as the current run, and marks it cancelled - so a new scan
can start immediately. The abandoned probe keeps running on its daemon thread
until its timeout, then sees ``cancelled`` and discards whatever it gathered
instead of storing it. A green ``context.presenter.notify(...)`` line announces
a real completion regardless of the user's current context.

Hosts can also be identified *without probing* by importing a pcap (e.g. one a
``capture export`` produced): :meth:`import_hosts` records every sender it sees
as up. See :func:`_active_hosts_from_packets`.

Service (port/version) discovery is a stub for now - see :meth:`scan_services`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.discovery.host import METHODS, Host
from mac_and_seize.net.adapters import netifaces_io, scapy_io
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.core.tasks import Task

#: Default seconds to wait for probe replies when the user gives no --timeout.
_DEFAULT_TIMEOUT = 3

#: Each probe method mapped to a callable ``(hosts, timeout, iface) ->
#: {ip: mac|None}`` over the shared scapy adapter. Only the layer-2 ARP sweep
#: can be pinned to a NIC (``iface``); the layer-3 ICMP sweep is kernel-routed
#: and ignores it (see :func:`scapy_io.icmp_probe`). ARP yields a MAC; ICMP echo
#: (``ping``) yields the IP only.
_PROBES: dict[str, Callable[[list[str], int, str | None], dict[str, str | None]]] = {
    "arp": lambda hosts, timeout, iface: dict(
        scapy_io.arp_probe(hosts, timeout=timeout, iface=iface)
    ),
    "ping": lambda hosts, timeout, _iface: {
        ip: None for ip in scapy_io.icmp_probe(hosts, timeout=timeout)
    },
}

#: Source addresses that identify no real host (never treated as active).
_NON_HOST_SOURCES = {"0.0.0.0", "::"}


def _active_hosts_from_packets(packets: list) -> dict[str, str | None]:
    """Map each active source address in ``packets`` to a MAC (or ``None``).

    A host counts as active only if it *sent* a packet: a source address is a
    live sender, whereas a destination may be unreachable, broadcast, or
    multicast. ARP gives an authoritative IP<->MAC binding on the local link and
    always wins; for other traffic the layer-2 source MAC is recorded only as a
    best-effort hint that never overwrites an ARP-learned one (for routed
    traffic that MAC is the gateway's, not the source address's). An address
    seen without any usable MAC is still recorded (mapped to ``None``).
    """
    hosts: dict[str, str | None] = {}
    arp_confirmed: set[str] = set()
    for packet in packets:
        info = packet.info()
        ip = info.get("src_ip")
        if not ip or ip in _NON_HOST_SOURCES:
            continue
        mac = info.get("src_mac")
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            mac = None
        hosts.setdefault(ip, None)  # record the sender even with no MAC yet
        if mac is None:
            continue
        if "arp_op" in info:  # ARP psrc<->hwsrc is a real binding, so it wins
            hosts[ip] = mac
            arp_confirmed.add(ip)
        elif ip not in arp_confirmed and hosts[ip] is None:
            hosts[ip] = mac  # best-effort fill of a still-unknown MAC
    return hosts


@dataclass
class _Run:
    """One in-flight scan, tracked by identity so cancelling can *detach* it.

    Because a blocking ``sr``/``srp`` sweep can't be interrupted, cancel doesn't
    wait for it: it clears this run as the service's current run and flips
    ``cancelled``, freeing the service to start another scan at once. This run's
    own worker thread keeps draining in the background and, seeing ``cancelled``,
    throws its results away instead of merging them.
    """

    target: str
    iface: str | None
    task: "Task"
    context: "AppContext"
    thread: threading.Thread | None = None
    cancelled: bool = False


class DiscoveryService:
    """Background scapy host discovery with a per-session store of hosts found.

    Scanning requires root (raw sockets); callers (the CLI) gate root-only
    actions before running them.
    """

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._hosts: dict[str, Host] = {}
        #: The current (foreground) scan, or ``None``. Cancelling detaches it by
        #: setting this back to ``None`` even while its thread is still draining.
        self._run: _Run | None = None

    # --- Background scan -------------------------------------------------------

    def is_scanning(self) -> bool:
        with self._lock:
            run = self._run
            return run is not None and run.thread is not None and run.thread.is_alive()

    def start_scan(
        self,
        context: "AppContext",
        target: str,
        *,
        method: str = "all",
        timeout: int | None = None,
    ) -> str:
        """Start a background host-discovery scan against ``target``."""
        target = target.strip()
        if not target:
            raise ValueError("A scan target is required (e.g. an IP, CIDR, or range).")
        if method not in METHODS:
            raise ValueError(
                f"Unknown method {method!r}. Supported: {', '.join(METHODS)}."
            )
        if timeout is not None and timeout <= 0:
            raise ValueError("--timeout must be a positive number of seconds.")
        wait = timeout or _DEFAULT_TIMEOUT
        # Resolve up front (synchronously) so a bad interface / bad or oversized
        # address target fails now, before a background task is registered.
        iface, hosts = self._resolve_target(target)
        methods = METHODS[method]

        with self._lock:
            if self.is_scanning():
                raise ModuleError(
                    "A scan is already running. Cancel it before starting another."
                )
            run = _Run(
                target=target,
                iface=iface,
                task=context.tasks.start(context.current_command, stop=self.cancel_scan),
                context=context,
            )
            run.thread = threading.Thread(
                target=self._run_scan,
                args=(run, hosts, methods, wait),
                daemon=True,
            )
            self._run = run
            run.thread.start()
        self._log.info(
            "Discovery scan started (target=%s, iface=%s, method=%s, hosts=%d)",
            target, iface or "default", method, len(hosts),
        )
        return (
            f"Scan started in the background for {target} "
            f"({len(hosts)} host(s))."
        )

    def _resolve_target(self, target: str) -> tuple[str | None, list[str]]:
        """Resolve a scan ``target`` to ``(iface, hosts)``.

        If ``target`` names a local interface, scan the subnet(s) that NIC is on
        and pin the probes to it (returned as ``iface``). Otherwise ``target``
        is an address spec (IP, CIDR, last-octet range, or hostname) scanned via
        scapy's default routing (``iface`` is ``None``). Raises
        :class:`ValueError` for an interface with no IPv4 address or a malformed
        address target.
        """
        if target in netifaces_io.list_names():
            networks = netifaces_io.ipv4_networks(target)
            if not networks:
                raise ValueError(
                    f"Interface {target!r} has no IPv4 address to derive a subnet "
                    "from; give an address range instead."
                )
            hosts: list[str] = []
            for network in networks:
                hosts.extend(scapy_io.expand_hosts(network))
            return target, list(dict.fromkeys(hosts))  # dedup, keep order
        return None, scapy_io.expand_hosts(target)

    def cancel_scan(self) -> str:
        """Cancel the running scan at once and let a new one start immediately.

        The in-flight scapy probe can't be interrupted - ``sr``/``srp`` have no
        cooperative stop hook - so instead of waiting for it we *detach* the run:
        clear it as the current scan, mark it cancelled, and drop its task. A new
        scan can start right away; the abandoned probe drains on its own daemon
        thread and discards its results. See ``modules/README.md`` §9.
        """
        with self._lock:
            run = self._run
            if run is None or run.thread is None or not run.thread.is_alive():
                raise ModuleError("No scan is currently running.")
            run.cancelled = True
            self._run = None  # detach now, so start_scan is free again
        run.context.tasks.finish(run.task)
        self._log.info("Discovery scan cancelled (target=%s)", run.target)
        return (
            "Scan cancelled (the abandoned "
            "probe finishes on its own in the background, but the results will be "
            "discarded)."
        )

    def _run_scan(
        self,
        run: _Run,
        hosts: list[str],
        methods: tuple[str, ...],
        timeout: int,
    ) -> None:
        target = run.target
        # ip -> (mac|None, method that found it). ARP runs before ping, so a
        # host found on-link keeps its MAC and isn't re-probed by ping.
        replies: dict[str, tuple[str | None, str]] = {}
        error: Exception | None = None
        try:
            # One sweep per method over the hosts not yet found up. Checking
            # cancellation between methods lets a cancel during the ARP sweep
            # skip the ICMP sweep (the in-flight probe still runs to timeout).
            remaining = set(hosts)
            for method in methods:
                if not remaining or run.cancelled:
                    break
                found = _PROBES[method](sorted(remaining), timeout, run.iface)
                for ip, mac in found.items():
                    if ip in remaining:
                        replies[ip] = (mac, method)
                        remaining.discard(ip)
        except PermissionError as exc:
            error = ModuleError(
                "Host discovery needs raw-socket access; relaunch as root (sudo)."
            )
            self._log.info("Discovery scan denied (not root): %s", exc)
        except OSError as exc:
            error = ModuleError(f"Scan of {target} failed: {exc}")
        except Exception as exc:  # noqa: BLE001 - report, never crash the worker thread
            error = exc

        # Read cancelled and merge under one lock acquisition: a cancel can only
        # detach this run (never leave it current), so `not cancelled` means we
        # are still the current run and it is safe to commit our hosts.
        found_count = 0
        with self._lock:
            cancelled = run.cancelled
            if self._run is run:
                self._run = None
            if not cancelled and error is None:
                found_count = self._merge_locked(replies)

        run.context.tasks.finish(run.task)  # idempotent; cancel may already have

        if cancelled:
            self._log.info("Discarded result of cancelled scan (target=%s)", target)
            return
        if error is not None:
            self._log.warning("Discovery scan failed (target=%s): %s", target, error)
            run.context.presenter.notify(f"Discovery scan of {target} failed: {error}")
            return
        run.context.presenter.notify(
            f"Discovery scan of {target} finished: {found_count} host(s) found."
        )

    def _merge_locked(self, replies: dict[str, tuple[str | None, str]]) -> int:
        """Merge a completed sweep's replies into the store. Caller holds ``_lock``."""
        now = datetime.now(timezone.utc)
        for ip, (mac, method) in replies.items():
            existing = self._hosts.get(ip)
            self._hosts[ip] = Host(
                ip=ip,
                mac=mac,
                vendor=scapy_io.mac_vendor(mac),
                state="up",
                method=method,
                first_seen=existing.first_seen if existing else now,
                last_seen=now,
            )
        return len(replies)

    # --- Import from capture ----------------------------------------------------

    def import_hosts(self, fmt: str, filename: str) -> int:
        """Identify active hosts from a pcap and merge them into the store.

        Reads ``filename`` (only the ``pcap`` format, like ``capture import``)
        and records every host that *sent* a packet as up, with its MAC where
        the capture reveals one (ARP bindings preferred; see
        :func:`_active_hosts_from_packets`). Returns the number of active hosts
        identified. Needs no privileges - it only reads a file, sending nothing.
        """
        normalized = fmt.lower().lstrip(".")
        if normalized != "pcap":
            raise ModuleError(
                f"Unsupported import format {fmt!r}; only 'pcap' is supported."
            )
        path = Path(filename)
        if not path.is_file():
            raise ModuleError(f"File not found: {filename}.")
        try:
            packets = scapy_io.read_pcap(str(path))
        except ModuleError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface any read/parse failure cleanly
            raise ModuleError(f"Could not read {filename}: {exc}") from exc

        replies = {
            ip: (mac, "pcap")
            for ip, mac in _active_hosts_from_packets(packets).items()
        }
        with self._lock:
            self._merge_locked(replies)
        self._log.info(
            "Imported %d active host(s) from %s (%d packet(s))",
            len(replies), path, len(packets),
        )
        return len(replies)

    # --- Session store ----------------------------------------------------------

    def clear(self) -> int:
        with self._lock:
            count = len(self._hosts)
            self._hosts.clear()
            self._log.info("Cleared %d discovered host(s)", count)
            return count

    def list_hosts(self) -> list[dict]:
        with self._lock:
            return [host.as_row() for host in self._hosts.values()]

    def summary(self) -> dict:
        with self._lock:
            hosts = list(self._hosts.values())
            scanning = self.is_scanning()
        methods: dict[str, int] = {}
        for host in hosts:
            methods[host.method] = methods.get(host.method, 0) + 1
        return {
            "hosts": len(hosts),
            "with_mac": sum(1 for host in hosts if host.mac),
            "with_vendor": sum(1 for host in hosts if host.vendor),
            "by_method": ", ".join(f"{k}={v}" for k, v in sorted(methods.items())),
            "scanning": scanning,
        }

    # --- Service discovery (stub) -------------------------------------------------

    def scan_services(self, ip: str) -> None:
        raise ModuleError(
            "Service discovery is not implemented yet; host discovery is "
            "available via 'discovery host scan'."
        )

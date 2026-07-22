"""Discover live hosts on the network (the discovery module's session service).

Like ``CaptureService``, this is instantiated once per
:class:`~mac_and_seize.core.context.AppContext` and holds session state: hosts
found so far, keyed by IP so repeat scans refresh an already-known host
instead of duplicating it. A scan ARP-probes the target (via the shared scapy
adapter - no external ``nmap`` binary) in a background thread so the prompt
stays responsive; only one scan may run at a time.

A scan target is either an **address spec** (IP, CIDR, last-octet range, or
hostname) scanned via the default route, or the name of a **local interface**,
in which case the subnet that NIC is on is scanned and the probes are pinned to
that interface (so multi-homed hosts can scan the right link), or the keyword
``"discovered"`` to re-probe every host already in the store (a fast liveness
recheck). See :meth:`_resolve_target`. ARP is not routed, so a scan only finds
hosts on the local link; the whole target is swept in one batch.

A completed host scan sets each host's ``state`` relative to that scan -
``"up"`` (replied), ``"down"`` (in range but silent), or ``"N/A"`` (outside the
scan's range) - and flags hosts it saw for the first time as new; see
:meth:`_merge_scan_locked`.

The probe is a pure-scapy ARP sweep inspired by nmap's ``-PR`` host discovery;
none of nmap's code is used.

scapy's ``srp`` blocks until its timeout with no cooperative interrupt point, so
a running probe cannot be stopped mid-flight. :meth:`cancel` is
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

There is a **single, host-oriented store** (``self._hosts``): host discovery,
pcap import, and service discovery all write into it. Service discovery -
:meth:`start_service_scan`, a background TCP SYN or UDP port scan - does not keep
its own list; each open port it finds is attached to its host as a
:class:`~mac_and_seize.modules.discovery.host.Port` (``Host.ports``), and a scan
that finds an open port on a not-yet-known IP creates that host (``method`` =
``"port"``). It reuses the store for the ``"discovered"`` target - scanning every
host found so far - and runs in its own background thread with the same
detach-on-cancel model as a host scan, tracked independently so a host scan and a
port scan can run at the same time (:meth:`cancel` stops whichever are running).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, TypeGuard

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.discovery.host import Host, Port, _ip_sort_key, host_rows
from mac_and_seize.net.adapters import netifaces_io, scapy_io
from mac_and_seize.observability import get_logger
from mac_and_seize.util.parse import split_values

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.core.tasks import Task

#: Default seconds to wait for ARP replies (per attempt) when the user gives no
#: --timeout. A reply on the local link returns in well under a millisecond, but
#: too short a wait misses hosts that are slow to answer (a busy or power-saving
#: host, a loaded switch), and scapy's sweep only ends early once *every* probe
#: is answered - which never happens when the target range covers unused
#: addresses - so it always blocks for the full timeout. This is per attempt and
#: :func:`~mac_and_seize.net.adapters.scapy_io.arp_probe` re-probes unanswered
#: addresses (3 attempts total), so an unused address is waited on ~3x this.
_DEFAULT_TIMEOUT = 1.0

#: Source addresses that identify no real host (never treated as active).
_NON_HOST_SOURCES = {"0.0.0.0", "::"}

#: Default seconds to wait for replies in a service (port) scan. Longer than the
#: ARP default because these probes are routed (higher RTT), and a filtered port
#: never answers so the scan always waits the full timeout per host - keep it
#: modest so a many-host scan does not crawl. The user can override with
#: ``--timeout`` (lower on a fast LAN, higher across a slow WAN).
_DEFAULT_SERVICE_TIMEOUT = 2.0

#: Default port spec when ``--port`` is omitted (the well-known + registered
#: range most services live in).
_DEFAULT_PORTS = "1-1000"

#: Upper bound on total probes (hosts x ports) a single service scan may send,
#: so an accidental huge sweep (a wide range across many hosts) is rejected up
#: front instead of flooding the network. A /24 at the default 1000 ports fits.
_MAX_PROBES = 262_144


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


def _alive(run: _Run | None) -> TypeGuard[_Run]:
    """True if ``run`` exists and its worker thread is still running.

    A :class:`~typing.TypeGuard` so a caller that guards on it may then touch
    ``run``'s fields without a separate ``None`` check.
    """
    return run is not None and run.thread is not None and run.thread.is_alive()


class DiscoveryService:
    """Background scapy host discovery with a per-session store of hosts found.

    Scanning requires root (raw sockets); callers (the CLI) gate root-only
    actions before running them.
    """

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        #: The single, host-oriented store: one Host per IP, each carrying its
        #: own open ports. Host discovery, pcap import, and port scans all merge
        #: into this.
        self._hosts: dict[str, Host] = {}
        #: The current host-discovery scan, or ``None``. Cancelling detaches it by
        #: setting this back to ``None`` even while its thread is still draining.
        self._run: _Run | None = None
        #: The current port scan, tracked separately from ``_run`` so a host scan
        #: and a port scan can run at the same time.
        self._svc_run: _Run | None = None

    # --- Background scan -------------------------------------------------------

    def is_scanning(self) -> bool:
        with self._lock:
            return _alive(self._run)

    def start_scan(
        self,
        context: "AppContext",
        target: str,
        *,
        timeout: float | None = None,
    ) -> str:
        """Start a background ARP host-discovery scan against ``target``."""
        target = target.strip()
        if not target:
            raise ValueError("A scan target is required (e.g. an IP, CIDR, or range).")
        if timeout is not None and timeout <= 0:
            raise ValueError("--timeout must be a positive number of seconds.")
        wait = timeout or _DEFAULT_TIMEOUT
        # Rebuild scapy's interface/route caches (stale since launch if the wire
        # moved to another NIC), so the sweep leaves the link that is actually up
        # now instead of a cached, now-dead one.
        scapy_io.refresh_network_state()
        # Resolve up front (synchronously) so a bad interface / bad or oversized
        # address target fails now, before a background task is registered.
        iface, hosts = self._resolve_target(target)

        with self._lock:
            if self.is_scanning():
                raise ModuleError(
                    "A scan is already running. Cancel it before starting another."
                )
            run = _Run(
                target=target,
                iface=iface,
                task=context.tasks.start(context.current_command, stop=self.cancel),
                context=context,
            )
            run.thread = threading.Thread(
                target=self._run_scan,
                args=(run, hosts, wait),
                daemon=True,
            )
            self._run = run
            run.thread.start()
        self._log.info(
            "Discovery scan started (target=%s, iface=%s, hosts=%d)",
            target, iface or "default", len(hosts),
        )
        return (
            f"Scan started in the background for {target} "
            f"({len(hosts)} host(s))."
        )

    def _resolve_target(self, target: str) -> tuple[str | None, list[str]]:
        """Resolve a scan ``target`` to ``(iface, hosts)``.

        The keyword ``"discovered"`` expands to every IP found so far (routed, so
        ``iface`` is ``None``) - a quick way to re-probe the whole store and see
        which hosts are still up. If ``target`` names a local interface, scan the
        subnet(s) that NIC is on and pin the probes to it (returned as
        ``iface``). Otherwise ``target`` is an address spec (IP, CIDR, last-octet
        range, or hostname) scanned via scapy's default routing (``iface`` is
        ``None``). Raises :class:`ValueError` for an interface with no IPv4
        address or a malformed address target, and :class:`ModuleError` for
        ``"discovered"`` with an empty store.
        """
        if target.lower() == "discovered":
            with self._lock:
                hosts = sorted({host.ip for host in self._hosts.values()}, key=_ip_sort_key)
            if not hosts:
                raise ModuleError(
                    "No hosts discovered yet to scan; run 'discovery scan' with an "
                    "explicit target first."
                )
            return None, hosts
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

    def cancel(self) -> str:
        """Cancel whichever discovery scans are running (host and/or port).

        A host scan and a port scan run in independent slots, so this stops
        both if both are in flight. Cancelling is *instant by detachment*: the
        in-flight scapy probe can't be interrupted (``sr``/``srp`` have no
        cooperative stop hook), so rather than wait for it we clear the run as
        current, mark it cancelled, and drop its task - a new scan can start at
        once, and the abandoned probe drains on its own daemon thread and
        discards its results. See ``modules/README.md`` §9.
        """
        cancelled: list[_Run] = []
        labels: list[str] = []
        with self._lock:
            host_run = self._run
            if _alive(host_run):
                host_run.cancelled = True
                self._run = None  # detach now, so start_scan is free again
                cancelled.append(host_run)
                labels.append("host scan")
            svc_run = self._svc_run
            if _alive(svc_run):
                svc_run.cancelled = True
                self._svc_run = None  # detach now, so start_service_scan is free again
                cancelled.append(svc_run)
                labels.append("port scan")
        if not cancelled:
            raise ModuleError("No scan is currently running.")
        for run in cancelled:
            run.context.tasks.finish(run.task)
        self._log.info("Discovery cancelled: %s", ", ".join(labels))
        return (
            f"Cancelled {' and '.join(labels)} (the abandoned probe(s) finish on "
            "their own in the background, but the results will be discarded)."
        )

    def _run_scan(
        self,
        run: _Run,
        hosts: list[str],
        timeout: float,
    ) -> None:
        target = run.target
        # ip -> (mac, method that found it); the ARP sweep always reports "arp".
        replies: dict[str, tuple[str | None, str]] = {}
        error: Exception | None = None
        try:
            # A single ARP sweep over the whole target. The guard lets a cancel
            # that lands before the probe starts skip it entirely; once srp is
            # in flight it runs to its timeout (there is no cooperative stop).
            if not run.cancelled:
                found = scapy_io.arp_probe(
                    sorted(set(hosts)), timeout=timeout, iface=run.iface
                )
                for ip, mac in found.items():
                    replies[ip] = (mac, "arp")
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
                found_count = self._merge_scan_locked(set(hosts), replies)

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
        """Merge a completed sweep's replies into the store. Caller holds ``_lock``.

        Every replying host is recorded ``"up"`` and flagged ``is_new`` when this
        is the first time the store has seen its address. Preserves an
        already-known host's open ports (and doesn't wipe a known MAC with a reply
        that carries none), since host discovery and port scans share the one
        store. This only *adds* liveness for hosts that answered - re-evaluating
        the hosts that stayed silent (``down``/``N/A``) is the host scan's job, in
        :meth:`_merge_scan_locked`.
        """
        now = datetime.now(timezone.utc)
        prev_ips = set(self._hosts)
        for ip, (mac, method) in replies.items():
            existing = self._hosts.get(ip)
            mac = mac or (existing.mac if existing else None)
            self._hosts[ip] = Host(
                ip=ip,
                mac=mac,
                vendor=scapy_io.mac_vendor(mac),
                state="up",
                method=method,
                first_seen=existing.first_seen if existing else now,
                last_seen=now,
                ports=existing.ports if existing else {},
                is_new=ip not in prev_ips,
            )
        return len(replies)

    def _merge_scan_locked(
        self, scanned: set[str], replies: dict[str, tuple[str | None, str]]
    ) -> int:
        """Merge a host sweep and re-evaluate every host's liveness. Holds ``_lock``.

        The host scan is the authority on liveness, so it (re)sets the ``state``
        of *every* host in the store relative to the range it just covered:

        * a host that replied is ``"up"`` (and ``is_new`` if this scan first found
          it) - folded in by :meth:`_merge_locked`;
        * a host already known whose address was in ``scanned`` but stayed silent
          is ``"down"``;
        * a host whose address was not in ``scanned`` is ``"N/A"`` (its liveness
          is unknown after a scan that never probed it).

        ``is_new`` is cleared on every host that did not just reply, so the ``*``
        prefix only ever marks the most recent scan's fresh finds. Returns the
        number of hosts that replied.
        """
        found = self._merge_locked(replies)
        replied = set(replies)
        for ip, host in self._hosts.items():
            if ip in replied:
                continue
            host.is_new = False
            host.state = "down" if ip in scanned else "N/A"
        return found

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

    def list_rows(self) -> list[dict]:
        """Rows for ``discovery list``: ip, state, mac, and open ports (no vendor)."""
        with self._lock:
            return [
                {
                    "ip": row["ip"],
                    "state": row["state"],
                    "mac": row["mac"],
                    "ports": row["ports"],
                }
                for row in host_rows(self._hosts.values())
            ]

    def inspect_rows(self) -> list[dict]:
        """Rows for ``discovery inspect``: ip, mac, vendor, and open ports."""
        with self._lock:
            return host_rows(self._hosts.values())

    def summary(self) -> dict:
        with self._lock:
            hosts = list(self._hosts.values())
            scanning = self.is_scanning()
            port_scanning = self.is_service_scanning()
        methods: dict[str, int] = {}
        open_ports = 0
        hosts_with_ports = 0
        for host in hosts:
            methods[host.method] = methods.get(host.method, 0) + 1
            if host.ports:
                hosts_with_ports += 1
                open_ports += len(host.ports)
        return {
            "hosts": len(hosts),
            "with_mac": sum(1 for host in hosts if host.mac),
            "with_vendor": sum(1 for host in hosts if host.vendor),
            "unique_macs": len({host.mac for host in hosts if host.mac}),
            "open_ports": open_ports,
            "hosts_with_open_ports": hosts_with_ports,
            "by_method": ", ".join(f"{k}={v}" for k, v in sorted(methods.items())) or "-",
            "scanning": scanning,
            "port_scanning": port_scanning,
        }

    # --- Service (port) discovery -------------------------------------------------

    def is_service_scanning(self) -> bool:
        with self._lock:
            return _alive(self._svc_run)

    def start_service_scan(
        self,
        context: "AppContext",
        target: str,
        proto: str,
        *,
        port: str | None = None,
        timeout: float | None = None,
    ) -> str:
        """Start a background ``proto`` (``"tcp"``/``"udp"``) port scan of ``target``.

        ``target`` accepts the same forms as a host scan (IP, CIDR, last-octet
        range, hostname, or a local interface name) plus the keyword
        ``"discovered"``, which scans every host found by host discovery so far.
        ``port`` is a single port, a comma list, or an ``a-b`` range (default
        :data:`_DEFAULT_PORTS`). Only open results are stored - see
        :meth:`_run_service_scan`.
        """
        target = target.strip()
        if not target:
            raise ValueError("A scan target is required (e.g. an IP, range, or 'discovered').")
        proto = proto.lower()
        if proto not in ("tcp", "udp"):
            raise ValueError(f"Unknown protocol {proto!r}; expected 'tcp' or 'udp'.")
        if timeout is not None and timeout <= 0:
            raise ValueError("--timeout must be a positive number of seconds.")
        wait = timeout or _DEFAULT_SERVICE_TIMEOUT
        ports = self._parse_ports(port or _DEFAULT_PORTS)
        # Rebuild scapy's interface/route caches (stale since launch if the wire
        # moved to another NIC), so probes leave the link that is actually up now.
        scapy_io.refresh_network_state()
        # Resolve up front (synchronously) so a bad target / empty 'discovered'
        # store / oversized scan fails now, before a background task is registered.
        iface, hosts = self._resolve_target(target)
        if not hosts:
            raise ValueError(f"Target {target!r} expands to no hosts to scan.")
        total = len(hosts) * len(ports)
        if total > _MAX_PROBES:
            raise ValueError(
                f"That scan is {total} probes ({len(hosts)} host(s) x {len(ports)} "
                f"port(s)); the limit is {_MAX_PROBES}. Narrow --port or the target."
            )

        with self._lock:
            if self.is_service_scanning():
                raise ModuleError(
                    "A port scan is already running. Cancel it before starting another."
                )
            run = _Run(
                target=target,
                iface=iface,
                task=context.tasks.start(context.current_command, stop=self.cancel),
                context=context,
            )
            run.thread = threading.Thread(
                target=self._run_service_scan,
                args=(run, hosts, ports, proto, wait),
                daemon=True,
            )
            self._svc_run = run
            run.thread.start()
        self._log.info(
            "Port scan started (proto=%s, target=%s, iface=%s, hosts=%d, ports=%d)",
            proto, target, iface or "default", len(hosts), len(ports),
        )
        return (
            f"{proto.upper()} port scan started in the background for {target} "
            f"({len(hosts)} host(s) x {len(ports)} port(s))."
        )


    @staticmethod
    def _parse_ports(spec: str) -> list[int]:
        """Parse a ``--port`` spec into a deduped list of port numbers.

        Accepts a single port, a comma list (``22,80,443``), or an inclusive
        range (``1-1000``); mixtures work too (``22,80,8000-8100``). Raises
        :class:`ValueError` for a non-numeric or out-of-range (1-65535) port.
        """
        ports: list[int] = []
        for value in split_values(spec):
            if not value.isdigit():
                raise ValueError(
                    f"Invalid port {value!r}; expected a number, list (a,b,c), or "
                    "range (a-b)."
                )
            number = int(value)
            if not 1 <= number <= 65535:
                raise ValueError(f"Port {number} is out of range (1-65535).")
            ports.append(number)
        ports = list(dict.fromkeys(ports))  # dedup, keep order
        if not ports:
            raise ValueError("No ports to scan.")
        return ports

    def _run_service_scan(
        self,
        run: _Run,
        hosts: list[str],
        ports: list[int],
        proto: str,
        timeout: float,
    ) -> None:
        target = run.target
        # (ip, proto, port) -> state, for the open results worth storing.
        found: dict[tuple[str, str, int], str] = {}
        error: Exception | None = None
        try:
            for host in hosts:
                if run.cancelled:  # cancel takes effect between hosts
                    break
                try:
                    # No iface pin: an L3 SYN/UDP scan is routed, so the kernel
                    # picks the egress interface for each destination (an
                    # interface target already narrowed `hosts` to that NIC's
                    # subnet, which routes back out through it).
                    if proto == "tcp":
                        states = scapy_io.tcp_syn_scan(host, ports, timeout=timeout)
                    else:
                        states = scapy_io.udp_scan(host, ports, timeout=timeout)
                except PermissionError:
                    raise  # missing root affects every host - abort the whole scan
                except OSError as exc:
                    # A per-host failure (e.g. no route) must not kill the scan.
                    self._log.warning("Service scan of host %s failed: %s", host, exc)
                    continue
                self._collect(found, host, proto, ports, states)
        except PermissionError as exc:
            error = ModuleError(
                "Port scanning needs raw-socket access; relaunch as root (sudo)."
            )
            self._log.info("Service scan denied (not root): %s", exc)
        except Exception as exc:  # noqa: BLE001 - report, never crash the worker thread
            error = exc

        # Read cancelled and merge under one lock acquisition (see _run_scan): a
        # cancel can only detach this run, so `not cancelled` means we are still
        # current and it is safe to commit.
        open_count = 0
        filtered_count = 0
        with self._lock:
            cancelled = run.cancelled
            if self._svc_run is run:
                self._svc_run = None
            if not cancelled and error is None:
                open_count, filtered_count = self._merge_ports_locked(found)

        run.context.tasks.finish(run.task)  # idempotent; cancel may already have

        if cancelled:
            self._log.info("Discarded result of cancelled port scan (target=%s)", target)
            return
        if error is not None:
            self._log.warning("Port scan failed (target=%s): %s", target, error)
            run.context.presenter.notify(f"Port scan of {target} failed: {error}")
            return
        counts = [f"{open_count} open"]
        if filtered_count:
            counts.append(f"{filtered_count} open|filtered")
        run.context.presenter.notify(
            f"{proto.upper()} port scan of {target} finished: "
            f"{', '.join(counts)} port(s) found."
        )

    @staticmethod
    def _collect(
        found: dict[tuple[str, str, int], str],
        host: str,
        proto: str,
        ports: list[int],
        states: dict[int, str],
    ) -> None:
        """Record the *interesting* results from one host's scan into ``found``.

        For TCP, only the ports the probe reported ``"open"``. For UDP, ``"open"``
        ports plus any that never answered (recorded ``open|filtered`` - UDP
        silence is ambiguous); closed and filtered ports are dropped. Whether an
        ``open|filtered`` result is actually persisted is decided per host by
        :meth:`_merge_ports_locked`, which never fabricates a host from silence.
        """
        if proto == "tcp":
            for port, state in states.items():
                if state == "open":
                    found[(host, "tcp", port)] = "open"
            return
        for port in ports:
            state = states.get(port)
            if state == "open":
                found[(host, "udp", port)] = "open"
            elif state is None:  # no reply - open or filtered, can't tell apart
                found[(host, "udp", port)] = "open|filtered"

    def _merge_ports_locked(
        self, found: dict[tuple[str, str, int], str]
    ) -> tuple[int, int]:
        """Attach found ports to their hosts in the store. Caller holds ``_lock``.

        A genuine ``"open"`` port (a real reply) is proof the host is live, so it
        may create a host not yet in the store (state ``"up"``, ``method`` =
        ``"port"``). A UDP ``"open|filtered"`` port is only the *absence* of a
        reply, so on its own it is no proof of a host: it is attached only to a
        host already known live - one already in the store, or one this same scan
        proved live with a genuine open port - and is dropped for an
        otherwise-unknown IP, so a silent or unused address is never fabricated as
        a live host. An existing host keeps its identity (MAC/vendor/method); only
        its ports and ``last_seen`` are updated. Returns ``(open, open_filtered)``
        - the counts of ports actually persisted.
        """
        now = datetime.now(timezone.utc)
        # Decide liveness once, up front: an IP already stored, or one with a
        # genuine open reply anywhere in this scan. Computing it before the merge
        # keeps it order-independent - a later open still rescues the same host's
        # earlier open|filtered ports.
        live_ips = set(self._hosts)
        live_ips |= {ip for (ip, _p, _n), state in found.items() if state == "open"}
        open_count = 0
        filtered_count = 0
        for (ip, proto, port), state in found.items():
            if ip not in live_ips:
                continue  # only open|filtered on an unknown IP - no proof of a host
            host = self._hosts.get(ip)
            if host is None:
                host = Host(
                    ip=ip, mac=None, vendor=None, state="up", method="port",
                    first_seen=now, last_seen=now, is_new=True,
                )
                self._hosts[ip] = host
            existing = host.ports.get((proto, port))
            host.ports[(proto, port)] = Port(
                proto=proto,
                port=port,
                state=state,
                first_seen=existing.first_seen if existing else now,
                last_seen=now,
            )
            host.last_seen = now
            if state == "open":
                open_count += 1
            else:
                filtered_count += 1
        return open_count, filtered_count

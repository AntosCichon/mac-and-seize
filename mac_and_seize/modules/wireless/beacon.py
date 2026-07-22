"""802.11 beacon-flood ("spam") jobs for authorized wireless testing.

The injection counterpart to the wireless capture service: it reuses the same
monitor-mode radio lifecycle (:class:`~mac_and_seize.modules.wireless.radio.MonitorRadioMixin`)
but, instead of *receiving* frames, it *transmits* them - flooding IEEE 802.11
beacon frames that advertise a chosen network name (SSID) from a bogus (random,
locally-administered) BSSID/source address.

Each ``spam`` starts an independent background job keyed by the advertised
network, so several run at once and any one stops on its own. The first job puts
the radio into monitor mode and establishes the **channel plan**; the last job to
stop restores the radio - exactly like the capture service.

BSSID mode
----------
By default a job picks **one** bogus BSSID when it starts and beacons it steadily
(~10/s, like a real AP), so the network shows up as a normal, stable entry in a
phone's Wi-Fi list. ``--randomize`` instead sends a **fresh** bogus address on
every frame, so a scanner sees a stream of phantom access points - louder, but a
phone's available-networks list aggregates by BSSID and hides an SSID whose BSSID
never settles, so use ``--randomize`` for a flood observed in a Wi-Fi analyzer,
not to make one named network appear.

Channels
--------
A monitor radio is on one channel at a time, so the channel plan belongs to the
shared radio, not to a single job. By default a job hops across the card's 2.4
GHz channels in randomized order - 2.4 GHz because 5 GHz channels are frequently
flagged NO-IR by the regulatory domain, where an injected beacon never actually
leaves the radio (a real-world gotcha after a connection manager is killed and
the regdomain falls back to the restrictive world domain). ``--channel`` overrides
the plan with an explicit number / list / range (a single channel is fixed; a set
is hopped across); each beacon's contents are built to match the band of the
channel it goes out on. The plan is set by the first job; concurrent jobs share it.

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

#: Seconds the shared radio dwells on each channel when the plan hops several. A
#: few beacons land on each channel per visit, enough for a scanner passing
#: through to catch one.
BEACON_HOP_INTERVAL_S = 0.5

#: Ultimate fallback channel if the card reports no tunable 2.4 GHz channel.
DEFAULT_BEACON_CHANNEL = 1

#: 802.11 caps the SSID information element at 32 bytes.
_MAX_SSID_BYTES = 32

#: How many consecutive send failures end a job on their own. At ~10/s this is a
#: few seconds of a broken interface (e.g. the NIC vanished) - stop rather than
#: spin forever logging.
_MAX_CONSECUTIVE_FAILURES = 50

#: Supported-rates IE for a 2.4 GHz beacon: 1/2/5.5/11 Mbit/s basic (CCK/DSSS) +
#: 18/24/36/54 OFDM. The CCK basic rates only exist in 2.4 GHz.
_RATES_2GHZ = b"\x82\x84\x8b\x96\x24\x30\x48\x6c"

#: Supported-rates IE for a 5 GHz beacon: OFDM only (6/9/12/18/24/36/48/54), with
#: 6/12/24 marked basic. A 5 GHz beacon must not advertise the CCK rates above.
_RATES_5GHZ = b"\x8c\x12\x98\x24\xb0\x48\x60\x6c"


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
    """Build one 802.11 beacon advertising ``ssid`` from bogus address ``source``.

    The information elements are built for the band of ``channel`` - a 2.4 GHz
    frame carries CCK-capable rates and a DS Parameter Set element; a 5 GHz frame
    carries OFDM-only rates and omits the (DSSS-only) DS Parameter Set - so the
    frame is not rejected as malformed by clients on that band.
    """
    dot11 = Dot11(
        type=0,  # management
        subtype=8,  # beacon
        addr1="ff:ff:ff:ff:ff:ff",  # destination: broadcast
        addr2=source,  # transmitter / source address (the bogus AP)
        addr3=source,  # BSSID (same bogus address)
    )
    beacon = Dot11Beacon(cap="ESS")  # an open (unencrypted) infrastructure network
    ssid_elt = Dot11Elt(ID="SSID", info=ssid.encode("utf-8", "replace"))
    if channel <= 14:  # 2.4 GHz
        rates_elt = Dot11Elt(ID="Rates", info=_RATES_2GHZ)
        dsset_elt = Dot11Elt(ID="DSset", info=bytes([channel & 0xFF]))
        return RadioTap() / dot11 / beacon / ssid_elt / rates_elt / dsset_elt
    # 5 GHz: OFDM-only rates, no DSSS DS Parameter Set element.
    rates_elt = Dot11Elt(ID="Rates", info=_RATES_5GHZ)
    return RadioTap() / dot11 / beacon / ssid_elt / rates_elt


@dataclass
class BeaconJob:
    """One running beacon-spam job (one advertised SSID)."""

    ssid: str
    #: The bogus BSSID/source address. Used as-is every frame (stable AP), or as a
    #: placeholder ignored in favour of a fresh one per frame when ``randomize``.
    bssid: str
    randomize: bool
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
        # The single monitor interface all jobs share (one radio), its channel
        # plan, and the channel it is on right now (updated by the hopper). Set up
        # by the first job, torn down by the last.
        self._iface: str | None = None
        self._channels: list[int] = []
        self._current_channel: int | None = None
        self._hopper_stop: threading.Event | None = None
        self._hopper_thread: threading.Thread | None = None
        self._context: "AppContext | None" = None

    # --- Public API -----------------------------------------------------------

    def spam(
        self,
        context: "AppContext",
        bssid: str,
        *,
        duration: int | None = None,
        channel: str | None = None,
        randomize: bool = False,
    ) -> str:
        """Start a background job beaconing the network name ``bssid``.

        ``bssid`` is the network name (SSID) to advertise. By default the job
        beacons from a single bogus BSSID it picks now, so it appears as a stable
        AP; ``randomize`` sends a fresh bogus address on every frame (phantom-AP
        flood) instead. The first job prepares monitor mode and the channel plan:
        ``channel`` (a number/list/range) overrides the default of hopping the
        card's 2.4 GHz channels in random order. ``duration`` (seconds) makes this
        job stop itself. Raises if a job for the same name is already running.
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
            notes = ""
            if first:
                iface = self._setup_radio_locked(channel)
            else:
                iface = self._iface  # type: ignore[assignment]
                if channel:
                    notes = (
                        " NOTE: a beacon session is already running on "
                        f"{self._plan_description()}; --channel applies only to the "
                        "first job and was ignored."
                    )
            try:
                job = BeaconJob(
                    ssid=ssid,
                    bssid=_random_mac(),
                    randomize=bool(randomize),
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
                # The first job may have just set up the radio; undo it so we don't
                # strand the NIC in monitor mode with a running hopper.
                if first and not self._jobs:
                    self._teardown_iface_locked()
                raise
            plan = self._plan_description()

        addr = "randomized BSSID per frame" if randomize else f"BSSID {job.bssid}"
        limit = f", stopping after {int(duration)}s" if duration else ""
        return (
            f"Beacon spam started for {ssid!r} ({addr}) on {iface} ({plan}){limit}. "
            f"Stop it with 'wireless beacon stop {ssid}'.{notes}"
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
                channel = self._current_channel or DEFAULT_BEACON_CHANNEL
                source = _random_mac() if job.randomize else job.bssid
                try:
                    scapy_io.send_l2(_beacon_frame(job.ssid, source, channel), job.iface)
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

    def _setup_radio_locked(self, channel_spec: str | None) -> str:
        """Prepare the shared monitor interface and channel plan for the first job."""
        iface = self._ensure_monitor(None)  # may raise ModuleError (radio held, etc.)
        try:
            channels = self._resolve_channels(iface, channel_spec)
            self._channels = channels
            self._current_channel = channels[0]
            try:
                wireless.set_channel(iface, channels[0])
            except (ModuleError, ValueError) as exc:
                # A pinned/limited radio may refuse to tune; advertise the channel
                # anyway and inject on whatever it is parked on. Not fatal.
                self._log.debug(
                    "Beacon: initial tune of %s to channel %d failed: %s",
                    iface, channels[0], exc,
                )
            self._iface = iface
            if len(channels) > 1:
                self._start_hopper_locked(iface, channels)
        except BaseException:
            self._teardown_monitor(note=False)
            self._iface = None
            self._channels = []
            self._current_channel = None
            raise
        return iface

    def _resolve_channels(self, iface: str, channel_spec: str | None) -> list[int]:
        """The channel plan: explicit ``--channel`` if given, else random 2.4 GHz."""
        supported = set(wireless.supported_channels(iface))
        if channel_spec:
            valid, rejected = wireless.validate_channels(
                wireless.parse_channel_spec(channel_spec)  # raises ValueError on junk
            )
            if not valid:
                raise ValueError("No valid IEEE 802.11 channels in --channel.")
            tunable = [c for c in valid if c in supported]
            unsupported = [c for c in valid if c not in supported]
            if not tunable:
                raise ModuleError(
                    f"{iface} cannot tune any of the requested channel(s) {valid}. "
                    "It may be a 2.4 GHz-only radio, or these are 5 GHz/DFS channels "
                    "the driver does not support."
                )
            if rejected:
                self._log.info("beacon: excluding non-IEEE channels %s", rejected)
            if unsupported:
                self._log.info("beacon: %s cannot tune %s; skipped", iface, unsupported)
            return tunable
        # Default: the card's 2.4 GHz channels in randomized order (5 GHz is often
        # NO-IR, so an injected beacon there never transmits - see module docs).
        two_ghz = [c for c in wireless.band_2ghz_channels() if c in supported]
        if not two_ghz:
            two_ghz = sorted(supported) or [DEFAULT_BEACON_CHANNEL]
        random.shuffle(two_ghz)
        return two_ghz

    def _teardown_iface_locked(self) -> str:
        """Stop the hopper, restore the radio, clear shared state; return the note."""
        self._stop_hopper_locked()
        self._teardown_monitor()
        self._iface = None
        self._channels = []
        self._current_channel = None
        return self.pop_teardown_note()

    def _start_hopper_locked(self, iface: str, channels: list[int]) -> None:
        """Spawn a thread that retunes ``iface`` across ``channels`` (already >1)."""
        stop = threading.Event()

        def run() -> None:
            index = 0
            while not stop.is_set():
                index += 1
                channel = channels[index % len(channels)]
                try:
                    wireless.set_channel(iface, channel)
                    self._current_channel = channel
                except Exception as exc:  # noqa: BLE001 - a bad channel must not kill the hop
                    # Debug, not warning: this runs a few times a second.
                    self._log.debug(
                        "Beacon hop: could not tune %s to channel %d: %s",
                        iface, channel, exc,
                    )
                stop.wait(BEACON_HOP_INTERVAL_S)

        self._hopper_stop = stop
        self._hopper_thread = threading.Thread(
            target=run, name="wl-beacon-hopper", daemon=True
        )
        self._hopper_thread.start()
        self._log.info(
            "Beacon channel hopper started on %s (%d channels, %dms)",
            iface, len(channels), int(BEACON_HOP_INTERVAL_S * 1000),
        )

    def _stop_hopper_locked(self) -> None:
        """Signal and join the channel hopper, if one is running."""
        stop, thread = self._hopper_stop, self._hopper_thread
        self._hopper_stop = None
        self._hopper_thread = None
        if stop is not None:
            stop.set()
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=2.0)

    def _plan_description(self) -> str:
        """Human-readable description of the shared channel plan."""
        channels = self._channels
        if not channels:
            return "channel ?"
        if len(channels) == 1:
            return f"channel {channels[0]}"
        return f"hopping channels {','.join(str(c) for c in sorted(channels))}"

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

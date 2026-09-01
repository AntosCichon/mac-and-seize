"""Send and capture packets (the capture module's stateful session service).

Unlike a stateless helper, this service is instantiated once per
:class:`~mac_and_seize.core.context.AppContext` and therefore holds
**session state**: the packets captured so far, the active capture filters, and
the running background sniffer (if any). Captures run in the background via
scapy's :class:`AsyncSniffer` so the interactive prompt stays responsive; the
captured packets are appended to the session on stop.

The background-capture lifecycle (starting/reaping/stopping the sniffer and the
packet store) lives in the shared :class:`~mac_and_seize.net.session.PacketSession`
base, so this class only adds the **wired** concerns: the include/exclude filter
set, socket-level interface selection, and the summary/inspect views.

Two capture modes coexist and are mutually exclusive at any given moment:

* **filter-based** (``capture start``) - opens an :class:`AsyncSniffer` on the
  selected NICs and applies the current include/exclude filter set to every
  frame the wire yields. Sees the whole segment; keeps whatever the filters
  do not exclude.
* **relay-attached** (``capture start --relay``) - opens no sniffer. Subscribes
  to the shared :class:`~mac_and_seize.modules.relay.service.RelayService`'s
  fan-out hook so only frames the relay module is actually forwarding land
  in the packet store. A clean MiTM view; ignores the filter set entirely.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.capture.filters import (
    ACTIONS,
    FIELDS,
    PROTOCOLS,
    Filter,
    build_predicate,
    select_interfaces,
)
from mac_and_seize.net.adapters import scapy_io
from mac_and_seize.net.model.packet import Packet
from mac_and_seize.net.session import PacketSession
from mac_and_seize.util.parse import split_values

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.core.tasks import Task


class CaptureService(PacketSession):
    """Background packet capture with a per-session store of packets and filters.

    Sniffing requires root; callers (the CLI) gate root-only actions before
    running them. One-shot packet I/O (send/sniff/pcap) lives in the shared
    scapy adapter (:mod:`mac_and_seize.net.adapters.scapy_io`).
    """

    def __init__(self) -> None:
        super().__init__()
        self.filters: list[Filter] = []
        self._next_id = 1
        #: Relay-attached mode state (see class docstring). ``_relay_token`` is
        #: the subscriber token returned by RelayService; ``_relay_task`` is
        #: the entry in the task registry so ``tasks`` and ``capture stop``
        #: know something is running; ``_relay_received`` counts frames
        #: added to the store during this attach so ``stop`` can report it.
        self._relay_token: int | None = None
        self._relay_task: "Task | None" = None
        self._relay_context: "AppContext | None" = None
        self._relay_received: int = 0

    # --- Background capture ---------------------------------------------------

    def start(
        self,
        context: "AppContext",
        *,
        time: int | None = None,
        count: int | None = None,
        relay: bool = False,
    ) -> str:
        """Start a background capture using the current filter set.

        When ``relay`` is True, opens no sniffer and instead subscribes to the
        relay module's fan-out (see :class:`CaptureService` docstring). The
        two modes are mutually exclusive at any given time; starting one
        while the other is running raises :class:`ModuleError`.
        """
        if relay:
            if time is not None or count is not None:
                raise ValueError(
                    "--time/--count are not supported for relay-attached "
                    "capture; the relay decides when frames arrive."
                )
            return self._start_relay(context)
        with self._lock:
            if self._relay_token is not None:
                raise ModuleError(
                    "A relay-attached capture is already running "
                    "('capture start --relay'). Stop it first."
                )
            predicate = build_predicate(self.filters)
            # Interface filters are applied here, at the socket level: scapy only
            # tags a packet with its interface *after* lfilter runs, so the NIC
            # set must be chosen up front. include -> those NICs; exclude ->
            # drop them from the available set; no interface filter -> all NICs.
            try:
                available = scapy_io.available_interfaces()
            except Exception:  # noqa: BLE001
                available = []
            selected = select_interfaces(self.filters, available)
            if available and not selected:
                raise ModuleError(
                    "Interface filters exclude every available interface; "
                    "nothing to capture on."
                )
        outcome = self._launch(
            context, ifaces=selected, predicate=predicate, time=time, count=count
        )
        return self._start_message(
            outcome, time, count,
            noun="Capture", unit="packet", stop_hint="capture stop",
        )

    # --- Relay-attached capture -----------------------------------------------

    def _start_relay(self, context: "AppContext") -> str:
        """Attach the packet store to the relay's fan-out."""
        try:
            relay_service: Any = context.service("relay")
        except KeyError as exc:
            raise ModuleError(
                "The 'relay' module is not loaded; cannot start "
                "'capture start --relay'."
            ) from exc
        with self._lock:
            self._reap_locked()
            if self._sniffer is not None:
                raise ModuleError(
                    "A filter-based capture is already running "
                    "('capture start'). Stop it first."
                )
            if self._relay_token is not None:
                raise ModuleError(
                    "A relay-attached capture is already running. "
                    "Stop it before starting another."
                )
            if not relay_service.list_rows():
                raise ModuleError(
                    "No relay flows are running; start one with "
                    "'lan arp spoof --relay', 'lan dhcp server --relay' (or "
                    "--nat-relay), or 'lan stp spoof --relay <egress>'."
                )
            self._relay_received = 0
            self._relay_context = context
            self._relay_token = relay_service.subscribe_all(self._on_relayed)
            self._relay_task = context.tasks.start(
                context.current_command, stop=self._stop_relay
            )
        self._log.info(
            "Capture started in relay-attached mode (token=%d)",
            self._relay_token,
        )
        return (
            "Capture started in the background, attached to the relay "
            "fan-out (see 'relay list'). Filter set is ignored in this "
            "mode. Stop it with 'capture stop'."
        )

    def _on_relayed(self, pkt) -> None:
        """Sniffer-thread callback: wrap and append one relayed frame.

        Runs on the RelaySession's sniffer thread. Must not raise (any
        exception here bubbles into
        :meth:`~mac_and_seize.net.relay.RelaySession._on_packet`'s fan-out
        guard, which logs it and moves on).
        """
        try:
            packet = Packet.from_scapy(pkt)
        except Exception:  # noqa: BLE001 - never fail the sniffer over one bad frame
            self._log.debug("Capture: relay-attached wrap failed", exc_info=True)
            return
        with self._lock:
            self.packets.append(packet)
            self._relay_received += 1

    def _stop_relay(self) -> int:
        """Detach from the relay fan-out and finish the task. Returns count added."""
        with self._lock:
            token = self._relay_token
            task = self._relay_task
            context = self._relay_context
            received = self._relay_received
            self._relay_token = None
            self._relay_task = None
            self._relay_context = None
            self._relay_received = 0
        if token is not None and context is not None:
            try:
                context.service("relay").unsubscribe(token)
            except Exception:  # noqa: BLE001 - teardown must not raise
                self._log.debug(
                    "Capture: relay unsubscribe failed", exc_info=True
                )
        if task is not None and context is not None:
            context.tasks.finish(task)
        self._log.info(
            "Capture (relay-attached) stopped: %d frame(s) added", received
        )
        return received

    # --- Unified stop / is_capturing overrides -------------------------------

    def is_capturing(self) -> bool:
        with self._lock:
            self._reap_locked()
            return self._sniffer is not None or self._relay_token is not None

    def stop(self) -> int:
        """Stop whichever capture mode is active. Raises if neither is."""
        with self._lock:
            relay_active = self._relay_token is not None
            sniffer_active = self._sniffer is not None
        if relay_active:
            return self._stop_relay()
        if sniffer_active:
            return super().stop()
        raise ModuleError("No capture is currently running.")

    # --- Session store --------------------------------------------------------

    def summary(self) -> dict:
        with self._lock:
            self._reap_locked()
            packets = list(self.packets)
            capturing = self._sniffer is not None
            active_filters = len(self.filters)
        if not packets:
            return {
                "packets": 0,
                "active_filters": active_filters,
                "capturing": capturing,
            }
        sources: set[str] = set()
        destinations: set[str] = set()
        protocols: dict[str, int] = {}
        for packet in packets:
            info = packet.info()
            src = info.get("src_ip") or info.get("src_mac")
            dst = info.get("dst_ip") or info.get("dst_mac")
            if src:
                sources.add(str(src))
            if dst:
                destinations.add(str(dst))
            layer = packet.top_layer()
            protocols[layer] = protocols.get(layer, 0) + 1
        return {
            "packets": len(packets),
            "unique_sources": len(sources),
            "unique_destinations": len(destinations),
            "protocols": ", ".join(f"{k}={v}" for k, v in sorted(protocols.items())),
            "active_filters": active_filters,
            "capturing": capturing,
        }

    def inspect_rows(self) -> list[dict]:
        with self._lock:
            return [packet.inspect_row() for packet in self.packets]

    # --- Filters --------------------------------------------------------------

    def add_filters(self, action: str, field_values: dict[str, str | None]) -> list[Filter]:
        action = action.lower()
        if action not in ACTIONS:
            raise ValueError(
                f"Action must be one of {', '.join(ACTIONS)} (got {action!r})."
            )
        provided = [(f, field_values.get(f)) for f in FIELDS if field_values.get(f)]
        if not provided:
            raise ValueError(
                "Provide at least one field to filter on "
                f"({', '.join('--' + f for f in FIELDS)})."
            )
        created: list[Filter] = []
        with self._lock:
            for field, raw in provided:
                for value in split_values(raw):
                    self._validate_value(field, value)
                    entry = Filter(self._next_id, action, field, value)
                    self._next_id += 1
                    self.filters.append(entry)
                    created.append(entry)
        self._log.info("Added %d %s filter(s)", len(created), action)
        return created

    def remove_filters(self, spec: str) -> list[Filter]:
        spec = spec.strip()
        with self._lock:
            if spec.lower() == "all":
                removed = list(self.filters)
                self.filters.clear()
                if not removed:
                    raise ModuleError("There are no filters to remove.")
                return removed
            ids: set[int] = set()
            for token in split_values(spec):
                if not token.isdigit():
                    raise ValueError(f"Invalid filter id {token!r}; expected a number.")
                ids.add(int(token))
            removed = [f for f in self.filters if f.id in ids]
            if not removed:
                raise ModuleError(f"No filters match id(s): {spec}.")
            self.filters = [f for f in self.filters if f.id not in ids]
            self._log.info("Removed %d filter(s)", len(removed))
            return removed

    def list_filters(self) -> list[dict]:
        with self._lock:
            return [f.as_row() for f in self.filters]

    @staticmethod
    def _validate_value(field: str, value: str) -> None:
        if field == "protocol" and value.lower() not in PROTOCOLS and value.lower() not in (
            "icmpv6", "ipv4"
        ):
            raise ValueError(
                f"Unknown protocol {value!r}. Supported: {', '.join(PROTOCOLS)}."
            )
        if field == "port":
            if not value.isdigit() or not (0 <= int(value) <= 65535):
                raise ValueError(f"Invalid port {value!r}; expected 0-65535.")

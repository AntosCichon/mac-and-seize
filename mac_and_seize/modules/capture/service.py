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
"""

from __future__ import annotations

from typing import TYPE_CHECKING

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
from mac_and_seize.net.session import PacketSession
from mac_and_seize.util.parse import split_values

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext


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

    # --- Background capture ---------------------------------------------------

    def start(
        self, context: "AppContext", *, time: int | None = None, count: int | None = None
    ) -> str:
        """Start a background capture using the current filter set."""
        with self._lock:
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

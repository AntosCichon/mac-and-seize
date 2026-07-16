"""Send and capture packets (the capture module's stateful session service).

Unlike a stateless helper, this service is instantiated once per
:class:`~mac_and_seize.core.context.AppContext` and therefore holds
**session state**: the packets captured so far, the active capture filters, and
the running background sniffer (if any). Captures run in the background via
scapy's :class:`AsyncSniffer` so the interactive prompt stays responsive; the
captured packets are appended to the session on stop.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING

from scapy.all import AsyncSniffer, get_if_list, sniff, srp

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.capture.filters import (
    ACTIONS,
    FIELDS,
    PROTOCOLS,
    Filter,
    build_predicate,
    select_interfaces,
    split_values,
)
from mac_and_seize.modules.capture.net import Packet, read_pcap, write_pcap
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.core.tasks import Task

#: Relative export/target paths are resolved under this directory (created on
#: demand) instead of the current working directory.
DEFAULT_EXPORT_DIR = Path("exports")


class CaptureService:
    """Packet send/sniff plus a per-session store of packets and filters.

    Sniffing requires root; callers (the CLI) gate root-only actions before
    running them.
    """

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.RLock()
        self.packets: list[Packet] = []
        self.filters: list[Filter] = []
        self._next_id = 1
        self._sniffer: AsyncSniffer | None = None
        self._task: "Task | None" = None
        self._context: "AppContext | None" = None
        self._error: BaseException | None = None
        self._capture_ifaces: list[str] = []

    # --- Background capture ---------------------------------------------------

    def is_capturing(self) -> bool:
        with self._lock:
            self._reap_locked()
            return self._sniffer is not None

    def start(
        self, context: "AppContext", *, time: int | None = None, count: int | None = None
    ) -> str:
        """Start a background capture using the current filter set."""
        with self._lock:
            self._reap_locked()
            if self._sniffer is not None:
                raise ModuleError(
                    "A capture is already running. Stop it before starting another."
                )
            if time is not None and time <= 0:
                raise ValueError("--time must be a positive number of seconds.")
            if count is not None and count < 0:
                raise ValueError("--count cannot be negative.")

            self._error = None
            predicate = build_predicate(self.filters)
            # Interface filters are applied here, at the socket level: scapy only
            # tags a packet with its interface *after* lfilter runs, so the NIC
            # set must be chosen up front. include -> those NICs; exclude ->
            # drop them from the available set; no interface filter -> all NICs.
            try:
                available = get_if_list()
            except Exception:  # noqa: BLE001
                available = []
            selected = select_interfaces(self.filters, available)
            if available and not selected:
                raise ModuleError(
                    "Interface filters exclude every available interface; "
                    "nothing to capture on."
                )
            interfaces = selected or None
            self._capture_ifaces = list(selected)
            sniffer = AsyncSniffer(
                iface=interfaces,
                lfilter=predicate,
                store=True,
                timeout=time or None,
                count=count or 0,
            )
            sniffer.start()

            # A capture can fail immediately (no privileges, bad socket). Give
            # that a brief moment to surface so 'start' reports it instead of
            # leaving a phantom "running" task.
            thread = getattr(sniffer, "thread", None)
            if thread is not None:
                thread.join(0.1)
            if thread is not None and not thread.is_alive():
                exc = getattr(sniffer, "exception", None)
                if exc is not None:
                    raise ModuleError(f"Could not start capture: {exc}")
                # Finished instantly with no error (e.g. count already met).
                captured = [Packet.from_scapy(p) for p in getattr(sniffer, "results", None) or []]
                self.packets.extend(captured)
                return f"Capture finished immediately: {len(captured)} packet(s) added."

            self._sniffer = sniffer
            self._context = context
            self._task = context.tasks.start(context.current_command, stop=self.stop)
            self._log.info(
                "Capture started (time=%s, count=%s, filters=%d)",
                time, count, len(self.filters),
            )

        limits = []
        if count:
            limits.append(f"{count} packet(s)")
        if time:
            limits.append(f"{time}s")
        suffix = f" (stops after {' or '.join(limits)})" if limits else ""
        return f"Capture started in the background{suffix}. Use 'capture stop' to finish."

    def stop(self) -> int:
        """Stop the running capture, append its packets, return how many."""
        with self._lock:
            if self._sniffer is None:
                raise ModuleError("No capture is currently running.")
            count = self._finalize_locked()
            if self._error is not None:
                error, self._error = self._error, None
                raise ModuleError(f"Capture ended with an error: {error}")
            return count

    def _finished_locked(self) -> bool:
        """True once the background sniffer has stopped (cleanly or by crash)."""
        sniffer = self._sniffer
        if sniffer is None:
            return False
        thread = getattr(sniffer, "thread", None)
        return not sniffer.running or (thread is not None and not thread.is_alive())

    def _reap_locked(self) -> None:
        """Finalize a capture that stopped on its own (timeout/count/crash)."""
        if self._finished_locked():
            self._finalize_locked()

    def _finalize_locked(self) -> int:
        sniffer = self._sniffer
        if sniffer is None:
            return 0
        thread = getattr(sniffer, "thread", None)
        if sniffer.running and thread is not None and thread.is_alive():
            try:
                sniffer.stop()
            except Exception:  # noqa: BLE001 - stop races are non-fatal
                self._log.exception("Error stopping sniffer")
        self._error = getattr(sniffer, "exception", None)
        results = list(getattr(sniffer, "results", None) or [])
        # scapy tags packets with sniffed_on only when sniffing multiple
        # sockets; when we captured on a single interface it may be empty, so
        # stamp it ourselves for the inspect view.
        fallback = self._capture_ifaces[0] if len(self._capture_ifaces) == 1 else None
        captured = []
        for pkt in results:
            if fallback and not getattr(pkt, "sniffed_on", None):
                pkt.sniffed_on = fallback
            captured.append(Packet.from_scapy(pkt))
        self._capture_ifaces = []
        self.packets.extend(captured)
        if self._task is not None and self._context is not None:
            self._context.tasks.finish(self._task)
        self._sniffer = None
        self._task = None
        self._context = None
        self._log.info("Capture stopped: %d packet(s) added to session", len(captured))
        return len(captured)

    # --- Session store --------------------------------------------------------

    def clear(self) -> int:
        with self._lock:
            count = len(self.packets)
            self.packets.clear()
            self._log.info("Cleared %d session packet(s)", count)
            return count

    def export(self, fmt: str, filename: str) -> Path:
        normalized = fmt.lower().lstrip(".")
        if normalized != "pcap":
            raise ModuleError(
                f"Unsupported export format {fmt!r}; only 'pcap' is supported."
            )
        path = Path(filename)
        if not path.is_absolute():
            path = DEFAULT_EXPORT_DIR / path
        with self._lock:
            if not self.packets:
                raise ModuleError("No packets to export; capture something first.")
            try:
                return self.write_pcap(path, list(self.packets), append=False)
            except OSError as exc:
                raise ModuleError(
                    f"Could not write to {path}: {exc.strerror or exc}."
                ) from exc

    def import_file(self, fmt: str, filename: str) -> int:
        normalized = fmt.lower().lstrip(".")
        if normalized != "pcap":
            raise ModuleError(
                f"Unsupported import format {fmt!r}; only 'pcap' is supported."
            )
        path = Path(filename)
        if not path.is_file():
            raise ModuleError(f"File not found: {filename}.")
        try:
            packets = read_pcap(str(path))
        except ModuleError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface any read/parse failure cleanly
            raise ModuleError(f"Could not read {filename}: {exc}") from exc
        with self._lock:
            self.packets.extend(packets)
        self._log.info("Imported %d packet(s) from %s", len(packets), path)
        return len(packets)

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

    # --- Lower-level packet ops (unchanged) -----------------------------------

    def send(self, iface_name: str, packet: Packet, *, timeout: int = 5):
        """Send a packet and wait for a response at layer 2."""
        pkt = packet.build() if isinstance(packet, Packet) else packet
        self._log.info("Sending packet on %s: %s", iface_name, packet)
        answered, unanswered = srp(
            pkt, iface=iface_name, threaded=False, timeout=timeout, verbose=False
        )
        self._log.info(
            "Send complete on %s: %d answered, %d unanswered",
            iface_name,
            len(answered),
            len(unanswered),
        )
        return answered, unanswered

    def sniff(
        self,
        iface_name: str,
        *,
        count: int = 0,
        bpf_filter: str | None = None,
        timeout: int | None = None,
    ) -> list[Packet]:
        """Capture packets synchronously (kept for programmatic/one-shot use)."""
        self._log.info(
            "Sniffing on %s (count=%s, filter=%s, timeout=%s)",
            iface_name,
            count,
            bpf_filter,
            timeout,
        )
        captured = sniff(
            iface=iface_name, filter=bpf_filter, timeout=timeout, count=count
        )
        self._log.info("Captured %d packet(s) on %s", len(captured), iface_name)
        return [Packet.from_scapy(pkt) for pkt in captured]

    def write_pcap(
        self, path: str | Path, packets: list[Packet], *, append: bool = True
    ) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_pcap(str(path), packets, append=append)
        self._log.info("Wrote %d packet(s) to %s", len(packets), path)
        return path

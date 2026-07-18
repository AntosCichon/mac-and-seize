"""Shared background-capture lifecycle for the capture module's services.

Both the wired :class:`~mac_and_seize.modules.capture.service.CaptureService`
and the wireless
:class:`~mac_and_seize.modules.capture.wireless_service.WirelessCaptureService`
run a scapy :class:`AsyncSniffer` in the background, accumulate the captured
:class:`~mac_and_seize.net.Packet`\\ s in a per-session store, and expose the same
store operations (clear/export/import). That common machinery lives here as a
base class so neither service reimplements the sniffer lifecycle. What differs
per service - how interfaces and the packet predicate are chosen, and how
packets are filtered/summarised/inspected - stays in the subclass.

This is module-internal (see modules/README.md §9 on background work); it is not
shared vocabulary, so it stays in the module rather than in ``net/``.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING

from scapy.all import AsyncSniffer

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.net import Packet
from mac_and_seize.net.adapters import scapy_io
from mac_and_seize.observability import get_logger

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.core.tasks import Task

#: Relative export/target paths are resolved under this directory (created on
#: demand) instead of the current working directory.
DEFAULT_EXPORT_DIR = Path("exports")


class PacketSession:
    """A background packet-capture session with a store of captured packets.

    Holds the running :class:`AsyncSniffer` (if any) plus the packets captured
    so far. Subclasses drive it by building an interface list and an ``lfilter``
    predicate and calling :meth:`_launch`; everything about starting, reaping,
    stopping, and storing packets is handled here. Sniffing requires root;
    callers (the CLI) gate root-only actions before running them.
    """

    def __init__(self) -> None:
        self._log = get_logger(type(self).__module__)
        self._lock = threading.RLock()
        self.packets: list[Packet] = []
        self._sniffer: AsyncSniffer | None = None
        self._task: "Task | None" = None
        self._context: "AppContext | None" = None
        self._error: BaseException | None = None
        self._capture_ifaces: list[str] = []

    # --- Background capture lifecycle ----------------------------------------

    def is_capturing(self) -> bool:
        with self._lock:
            self._reap_locked()
            return self._sniffer is not None

    def _launch(
        self,
        context: "AppContext",
        *,
        ifaces: list[str] | None,
        predicate,
        time: int | None,
        count: int | None,
    ) -> tuple[str, int]:
        """Start an ``AsyncSniffer`` on ``ifaces`` with ``predicate``.

        Returns ``("immediate", n)`` if the capture completed instantly (e.g.
        the count was already satisfiable) with ``n`` packets stored, or
        ``("started", 0)`` if it is now running in the background. Raises
        :class:`ModuleError` if a capture is already running or the sniffer
        could not start (no privileges, bad socket).
        """
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
            self._capture_ifaces = list(ifaces) if ifaces else []
            sniffer = AsyncSniffer(
                iface=ifaces or None,
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
                captured = self._wrap(getattr(sniffer, "results", None) or [])
                self.packets.extend(captured)
                return ("immediate", len(captured))

            self._sniffer = sniffer
            self._context = context
            self._task = context.tasks.start(context.current_command, stop=self.stop)
            self._log.info(
                "Capture started (time=%s, count=%s)", time, count
            )
            return ("started", 0)

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

    def _wrap(self, results) -> list[Packet]:
        """Wrap raw scapy packets, stamping the capture interface when needed.

        scapy tags packets with ``sniffed_on`` only when sniffing multiple
        sockets; on a single interface it may be empty, so stamp it ourselves
        for the inspect view.
        """
        fallback = self._capture_ifaces[0] if len(self._capture_ifaces) == 1 else None
        wrapped: list[Packet] = []
        for pkt in results:
            if fallback and not getattr(pkt, "sniffed_on", None):
                pkt.sniffed_on = fallback
            wrapped.append(Packet.from_scapy(pkt))
        return wrapped

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
        captured = self._wrap(results)
        self._capture_ifaces = []
        self.packets.extend(captured)
        if self._task is not None and self._context is not None:
            self._context.tasks.finish(self._task)
        self._sniffer = None
        self._task = None
        self._context = None
        self._log.info("Capture stopped: %d packet(s) added to session", len(captured))
        return len(captured)

    @staticmethod
    def _start_message(
        outcome: tuple[str, int],
        time: int | None,
        count: int | None,
        *,
        noun: str,
        unit: str,
        stop_hint: str,
    ) -> str:
        """Render the user-facing message for a :meth:`_launch` outcome."""
        kind, n = outcome
        if kind == "immediate":
            return f"{noun} finished immediately: {n} {unit}(s) added."
        limits = []
        if count:
            limits.append(f"{count} {unit}(s)")
        if time:
            limits.append(f"{time}s")
        suffix = f" (stops after {' or '.join(limits)})" if limits else ""
        return f"{noun} started in the background{suffix}. Use '{stop_hint}' to finish."

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
            packets = scapy_io.read_pcap(str(path))
        except ModuleError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface any read/parse failure cleanly
            raise ModuleError(f"Could not read {filename}: {exc}") from exc
        with self._lock:
            self.packets.extend(packets)
        self._log.info("Imported %d packet(s) from %s", len(packets), path)
        return len(packets)

    def write_pcap(
        self, path: str | Path, packets: list[Packet], *, append: bool = True
    ) -> Path:
        """Write packets to ``path`` (creating parent dirs); returns the path."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        scapy_io.write_pcap(str(path), packets, append=append)
        self._log.info("Wrote %d packet(s) to %s", len(packets), path)
        return path

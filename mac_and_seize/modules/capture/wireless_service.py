"""802.11 (monitor-mode) capture session service.

The wireless counterpart to :class:`~mac_and_seize.modules.capture.service.CaptureService`.
It reuses the shared background-capture lifecycle
(:class:`~mac_and_seize.modules.capture.session.PacketSession`) but captures on a
single monitor-mode interface, filters with the 802.11 vocabulary
(bssid/ssid/type/subtype), and inspects frames as Dot11 rather than Ethernet.

Registered as a **second** service of the capture module (key
``"capture_wireless"``) so the wired and wireless stores/filters stay separate.
Sniffing requires root; the CLI gates the actions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.capture.filters import split_values
from mac_and_seize.modules.capture.session import PacketSession
from mac_and_seize.modules.capture.wireless_filters import (
    ACTIONS,
    FIELDS,
    SUBTYPE_NAMES,
    TYPE_NAMES,
    WirelessFilter,
    build_wireless_predicate,
)
from mac_and_seize.net import MacAddress
from mac_and_seize.net.adapters import wireless

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext


class WirelessCaptureService(PacketSession):
    """Background 802.11 capture with a per-session store of frames and filters."""

    def __init__(self) -> None:
        super().__init__()
        self.filters: list[WirelessFilter] = []
        self._next_id = 1

    # --- Background capture ---------------------------------------------------

    def start(
        self,
        context: "AppContext",
        interface: str,
        *,
        time: int | None = None,
        count: int | None = None,
    ) -> str:
        """Start a background 802.11 capture on a monitor-mode ``interface``."""
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("Specify the monitor-mode interface to capture on.")
        if not wireless.is_wireless(interface):
            raise ModuleError(f"{interface!r} is not a wireless interface.")
        mode = wireless.current_mode(interface)
        if mode != "monitor":
            raise ModuleError(
                f"{interface!r} is in {mode!r} mode; run "
                f"'interface mode {interface} monitor' first."
            )
        with self._lock:
            predicate = build_wireless_predicate(self.filters)
        outcome = self._launch(
            context, ifaces=[interface], predicate=predicate, time=time, count=count
        )
        return self._start_message(
            outcome, time, count,
            noun="Wireless capture", unit="frame", stop_hint="capture wireless stop",
        )

    # --- Session views --------------------------------------------------------

    def summary(self) -> dict:
        with self._lock:
            self._reap_locked()
            packets = list(self.packets)
            capturing = self._sniffer is not None
            active_filters = len(self.filters)
        if not packets:
            return {"frames": 0, "active_filters": active_filters, "capturing": capturing}
        bssids: set[str] = set()
        ssids: set[str] = set()
        subtypes: dict[str, int] = {}
        for packet in packets:
            info = packet.dot11_info()
            if info.get("bssid"):
                bssids.add(info["bssid"])
            if info.get("ssid"):
                ssids.add(info["ssid"])
            label = f"{info.get('type', '-')}/{info.get('subtype', '-')}"
            subtypes[label] = subtypes.get(label, 0) + 1
        return {
            "frames": len(packets),
            "unique_bssids": len(bssids),
            "unique_ssids": len(ssids),
            "frame_types": ", ".join(f"{k}={v}" for k, v in sorted(subtypes.items())),
            "active_filters": active_filters,
            "capturing": capturing,
        }

    def inspect_rows(self) -> list[dict]:
        with self._lock:
            packets = list(self.packets)
        rows: list[dict] = []
        for packet in packets:
            info = packet.dot11_info()

            def part(key: str) -> str:
                value = info.get(key)
                return "-" if value in (None, "") else str(value)

            rows.append({
                "timestamp": packet.timestamp(),
                "subtype": f"{part('type')}/{part('subtype')}",
                "transmitter": part("transmitter"),
                "receiver": part("receiver"),
                "bssid": part("bssid"),
                "ssid": part("ssid"),
            })
        return rows

    # --- Filters --------------------------------------------------------------

    def add_filters(
        self, action: str, field_values: dict[str, str | None]
    ) -> list[WirelessFilter]:
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
        created: list[WirelessFilter] = []
        with self._lock:
            for field, raw in provided:
                for value in split_values(raw):
                    self._validate_value(field, value)
                    entry = WirelessFilter(self._next_id, action, field, value)
                    self._next_id += 1
                    self.filters.append(entry)
                    created.append(entry)
        self._log.info("Added %d %s wireless filter(s)", len(created), action)
        return created

    def remove_filters(self, spec: str) -> list[WirelessFilter]:
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
            self._log.info("Removed %d wireless filter(s)", len(removed))
            return removed

    def list_filters(self) -> list[dict]:
        with self._lock:
            return [f.as_row() for f in self.filters]

    @staticmethod
    def _validate_value(field: str, value: str) -> None:
        if field == "type" and value.lower() not in TYPE_NAMES:
            raise ValueError(
                f"Unknown type {value!r}. Supported: {', '.join(TYPE_NAMES)}."
            )
        if field == "subtype" and value.lower() not in SUBTYPE_NAMES:
            raise ValueError(
                f"Unknown subtype {value!r}. Supported: {', '.join(sorted(SUBTYPE_NAMES))}."
            )
        if field == "bssid":
            MacAddress.parse(value)  # raises ValueError on a malformed address

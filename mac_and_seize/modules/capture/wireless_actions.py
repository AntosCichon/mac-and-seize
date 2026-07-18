"""Actions exposed by the capture module's ``capture wireless`` subgroup.

802.11 monitor-mode capture: ``start`` / ``stop`` (background capture on a
monitor interface), ``inspect`` (a scrollable Dot11 table) and a ``filter``
subgroup (``add`` / ``remove`` / ``show``) over the wireless filter vocabulary.
Handlers stay thin: they translate parsed values into calls on the
session-scoped :class:`WirelessCaptureService` and return plain data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param
from mac_and_seize.core.presenter import Column
from mac_and_seize.modules.capture.wireless_filters import FIELDS

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.capture.wireless_service import WirelessCaptureService

WIRELESS_SERVICE = "capture_wireless"

# Column layout for the wireless `inspect` table; addresses/SSID flex to fill.
_INSPECT_COLUMNS = [
    Column("timestamp", "timestamp", 10),
    Column("subtype", "type/subtype", 14),
    Column("transmitter", "transmitter", 20, flex=True),
    Column("receiver", "receiver", 20, flex=True),
    Column("bssid", "bssid", 18),
    Column("ssid", "ssid", 20, flex=True),
]

WIRELESS_GROUP_DESCRIPTIONS = {
    "capture.wireless": "Capture and inspect 802.11 (Wi-Fi) frames in monitor mode",
    "capture.wireless.filter": "Manage 802.11 include/exclude filters",
}


def _service(context: "AppContext") -> "WirelessCaptureService":
    return context.service(WIRELESS_SERVICE)  # type: ignore[return-value]


def _start(context: "AppContext", values: dict) -> str:
    return _service(context).start(
        context, values["interface"], time=values.get("time"), count=values.get("count")
    )


def _stop(context: "AppContext", values: dict) -> str:
    service = _service(context)
    added = service.stop()
    return f"Wireless capture stopped: {added} frame(s) added ({len(service.packets)} in session)."


def _inspect(context: "AppContext", values: dict):
    rows = _service(context).inspect_rows()
    if not rows:
        return "No 802.11 frames captured yet; run 'capture wireless start <iface>' first."
    context.presenter.table(rows, _INSPECT_COLUMNS, title="Captured 802.11 frames")
    return None


def _filter_add(context: "AppContext", values: dict) -> list[dict]:
    field_values = {field: values.get(field) for field in FIELDS}
    created = _service(context).add_filters(values["action"], field_values)
    return [entry.as_row() for entry in created]


def _filter_remove(context: "AppContext", values: dict) -> str:
    removed = _service(context).remove_filters(values["ids"])
    ids = ", ".join(str(entry.id) for entry in removed)
    return f"Removed {len(removed)} filter(s): {ids}."


def _filter_show(context: "AppContext", values: dict):
    filters = _service(context).list_filters()
    if not filters:
        return "No filters defined. Every 802.11 frame is captured."
    return filters


def build_wireless_actions() -> list[Action]:
    return [
        Action(
            "capture.wireless.start",
            "Start 802.11 capture",
            "Start capturing 802.11 frames in the background on a monitor-mode "
            "interface, using the current wireless filter set. The interface must "
            "already be in monitor mode (see 'interface mode') and tuned to a "
            "channel (see 'interface channel'). The prompt stays usable while it "
            "runs; stop it with 'capture wireless stop' (requires root).",
            _start,
            [
                Param("interface", "Monitor-mode interface to capture on (e.g. wlan0)"),
                Param("time", "Stop after N seconds (whole capture)", int,
                      required=False),
                Param("count", "Stop after N frames", int, required=False),
            ],
            [
                "capture wireless start wlan0",
                "capture wireless start wlan0 --time 30",
                "capture wireless start wlan0 --count 500 --time 60",
            ],
            requires_root=True,
        ),
        Action(
            "capture.wireless.stop",
            "Stop 802.11 capture",
            "Stop the running 802.11 capture and append its frames to the "
            "wireless session (requires root).",
            _stop,
            examples=["capture wireless stop"],
            requires_root=True,
        ),
        Action(
            "capture.wireless.inspect",
            "Inspect 802.11 frames",
            "Open a scrollable, read-only table of captured 802.11 frames "
            "(timestamp, type/subtype, transmitter/receiver/BSSID, SSID). "
            "Navigate with the arrow keys; press Esc, Enter or q to exit.",
            _inspect,
            examples=["capture wireless inspect"],
        ),
        Action(
            "capture.wireless.filter.add",
            "Add 802.11 filter(s)",
            "Add wireless capture filters. Structure: 'add <include|exclude> "
            "<fields>'. Each field value (comma list) becomes a separate filter "
            "with its own id. Include filters are OR'd; an exclude match always "
            "drops the frame. Fields: bssid, ssid, type (mgmt/ctrl/data), subtype "
            "(beacon/probe-req/probe-resp/auth/deauth/rts/cts/qos-data/...).",
            _filter_add,
            [
                Param("action", "include (capture matches) or exclude (drop matches)"),
                Param("bssid", "BSSID (AA:BB:CC:DD:EE:FF)", required=False),
                Param("ssid", "Network name(s)", required=False),
                Param("type", "Frame type: mgmt, ctrl or data", required=False),
                Param("subtype", "Frame subtype(s): beacon, deauth, qos-data, ...",
                      required=False),
            ],
            [
                "capture wireless filter add include --type mgmt --subtype beacon,probe-req",
                "capture wireless filter add include --bssid AA:BB:CC:DD:EE:FF",
                "capture wireless filter add exclude --subtype ack,cts,rts",
            ],
        ),
        Action(
            "capture.wireless.filter.remove",
            "Remove 802.11 filter(s)",
            "Remove wireless filters by id. Accepts a single id, a comma list, a "
            "numeric range, or the keyword 'all'.",
            _filter_remove,
            [Param("ids", "Filter id(s): e.g. 3, 1,4,5, 2-6, or 'all'")],
            [
                "capture wireless filter remove 3",
                "capture wireless filter remove 1,4-6",
                "capture wireless filter remove all",
            ],
        ),
        Action(
            "capture.wireless.filter.show",
            "Show 802.11 filters",
            "List all defined wireless filters with their ids so they can be removed.",
            _filter_show,
            examples=["capture wireless filter show"],
        ),
    ]

"""Actions exposed by the ``wireless`` module (802.11 monitor-mode toolkit).

The command surface is intentionally small: capture is the only verb. Putting a
radio into monitor mode exists only to enable capture, so it is done quietly
inside ``capture start`` (and restored on ``stop``) rather than exposed as
separate ``monitor``/``mode``/``channel`` commands - the same "quiet reversible
plumbing behind one intent" the wired ``interface`` module uses for route
preservation. Channel selection lives entirely in ``--sweep``.

* ``capture`` - start/stop plus inspect/networks/stations/summary/clear/
  export/import and a ``filter`` subgroup;
* ``activity`` - rank channels by traffic to choose a ``--sweep``.

Handlers stay thin. Attack tooling (deauth, handshake capture, ...) is planned to
land as further top-level ``wireless`` subgroups.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param
from mac_and_seize.core.presenter import Column
from mac_and_seize.modules.wireless.capture import DEFAULT_DWELL_MS
from mac_and_seize.modules.wireless.filters import FIELDS

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.wireless.capture import WirelessCaptureService

WIRELESS_CAPTURE_SERVICE = "wireless_capture"

# Column layout for the `wireless capture inspect` table; addresses/SSID flex.
_INSPECT_COLUMNS = [
    Column("timestamp", "timestamp", 10),
    Column("subtype", "type/subtype", 14),
    Column("transmitter", "transmitter", 20, flex=True),
    Column("receiver", "receiver", 20, flex=True),
    Column("bssid", "bssid", 18),
    Column("ssid", "ssid", 20, flex=True),
]

WIRELESS_GROUP_DESCRIPTIONS = {
    "wireless": "Capture and manipulate 802.11 (Wi-Fi) traffic in monitor mode",
    "wireless.capture": "Capture and inspect 802.11 frames",
    "wireless.capture.filter": "Manage 802.11 include/exclude filters",
}


def _capture(context: "AppContext") -> "WirelessCaptureService":
    return context.service(WIRELESS_CAPTURE_SERVICE)  # type: ignore[return-value]


def _start(context: "AppContext", values: dict) -> str:
    return _capture(context).start(
        context,
        values.get("target"),
        time=values.get("time"),
        count=values.get("count"),
        sweep=values.get("sweep"),
        interval=values.get("interval"),
    )


def _stop(context: "AppContext", values: dict) -> str:
    service = _capture(context)
    added = service.stop()
    note = service.pop_teardown_note()
    return (
        f"Wireless capture stopped: {added} frame(s) added "
        f"({len(service.packets)} in session).{note}"
    )


def _activity(context: "AppContext", values: dict):
    service = _capture(context)
    rows, rejected = service.scan_activity(
        values.get("target"),
        values.get("channels") or "all",
        values.get("dwell") or DEFAULT_DWELL_MS,
    )
    if not rows:
        return "No channels could be scanned (the card may not tune any of them)."
    table: list[dict] = []
    if rejected:
        table.append({"channel": f"excluded {rejected}", "frames": "-", "beacons": "-",
                      "bytes": "-", "status": "not IEEE 802.11 channels"})
    table.extend(rows)
    # If channels refused to tune, a radio pinned to one channel is the usual
    # cause; append a one-line, actionable explanation as a final note row. The
    # scan already restored the radio, so the hint is the daemon/driver one
    # (interface-independent).
    if any(str(row.get("status", "")).startswith("tune failed") for row in rows):
        table.append({"channel": "note", "frames": "-", "beacons": "-", "bytes": "-",
                      "status": service.radio_hint()})
    return table


def _inspect(context: "AppContext", values: dict):
    rows = _capture(context).inspect_rows()
    if not rows:
        return "No 802.11 frames captured yet; run 'wireless capture start' first."
    context.presenter.table(rows, _INSPECT_COLUMNS, title="Captured 802.11 frames")
    return None


def _networks(context: "AppContext", values: dict):
    rows = _capture(context).networks()
    if not rows:
        return "No access points seen yet (no beacons/probe responses captured)."
    return rows


def _stations(context: "AppContext", values: dict):
    rows = _capture(context).stations()
    if not rows:
        return "No client stations seen yet."
    return rows


def _summary(context: "AppContext", values: dict) -> dict:
    return _capture(context).summary()


def _clear(context: "AppContext", values: dict) -> str:
    cleared = _capture(context).clear()
    return f"Cleared {cleared} frame(s) from the wireless session."


def _export(context: "AppContext", values: dict) -> str:
    path = _capture(context).export(values["format"], values["filename"])
    return f"Exported wireless session frames to {path}."


def _import(context: "AppContext", values: dict) -> str:
    service = _capture(context)
    added = service.import_file(values["format"], values["filename"])
    return f"Imported {added} frame(s) from {values['filename']} ({len(service.packets)} in session)."


def _filter_add(context: "AppContext", values: dict) -> list[dict]:
    field_values = {field: values.get(field) for field in FIELDS}
    created = _capture(context).add_filters(values["action"], field_values)
    return [entry.as_row() for entry in created]


def _filter_remove(context: "AppContext", values: dict) -> str:
    removed = _capture(context).remove_filters(values["ids"])
    ids = ", ".join(str(entry.id) for entry in removed)
    return f"Removed {len(removed)} filter(s): {ids}."


def _filter_show(context: "AppContext", values: dict):
    filters = _capture(context).list_filters()
    if not filters:
        return "No filters defined. Every 802.11 frame is captured."
    return filters


def build_wireless_actions() -> list[Action]:
    return [
        Action(
            "wireless.capture.start",
            "Start 802.11 capture",
            "Start capturing 802.11 frames in the background, using the current "
            "wireless filter set (requires root). Give a wireless interface "
            "(wlan0), a PHY (phy0), or nothing to use the only radio. The radio is "
            "put into monitor mode automatically and restored when you 'wireless "
            "capture stop' - a managed interface is switched to monitor (and back), "
            "or a dedicated monitor interface is created on a free radio (and "
            "removed). While capturing, that interface has no network connectivity. "
            "The tool never stops your connection manager itself: if one is holding "
            "the radio it says so and points at the fix. --sweep picks the "
            "channel(s): a single channel is tuned for the whole capture, a "
            "list/range/'all' hops across them every --interval ms (monitor mode "
            "only sees one channel at a time). The prompt stays usable while it "
            "runs.",
            _start,
            [
                Param("target", "Wireless interface (wlan0), PHY (phy0), or omit for the only radio",
                      required=False),
                Param("time", "Stop after N seconds (whole capture)", int,
                      required=False),
                Param("count", "Stop after N frames", int, required=False),
                Param("sweep", "Channel(s): a number, list (1,6,11), range (1-11), or 'all'",
                      required=False),
                Param("interval", "Milliseconds between channel hops (default 250)", int,
                      required=False),
            ],
            [
                "wireless capture start",
                "wireless capture start wlan0 --sweep 6",
                "wireless capture start phy0 --sweep 1,6,11 --interval 300",
                "wireless capture start --sweep all --time 60",
            ],
            requires_root=True,
        ),
        Action(
            "wireless.capture.stop",
            "Stop 802.11 capture",
            "Stop the running 802.11 capture (and its channel sweep, if any), "
            "append its frames to the wireless session, and restore the radio to "
            "how it was found - reverting monitor mode to managed, or removing a "
            "monitor interface the capture created (requires root).",
            _stop,
            examples=["wireless capture stop"],
            requires_root=True,
        ),
        Action(
            "wireless.activity",
            "Scan channel activity",
            "Dwell briefly on each channel and rank them by traffic (frames, "
            "beacons, bytes) so you can pick the busiest channels for a --sweep "
            "(requires root). Give a wireless interface, a PHY, or nothing for the "
            "only radio; it is put into monitor mode for the scan and restored "
            "afterwards. Blocks for roughly len(channels) x --dwell.",
            _activity,
            [
                Param("target", "Wireless interface, PHY, or omit for the only radio",
                      required=False),
                Param("channels", "Channels to scan: number, list, range, or 'all' (default all)",
                      required=False),
                Param("dwell", "Milliseconds to dwell per channel (default 250)", int,
                      required=False),
            ],
            [
                "wireless activity",
                "wireless activity wlan0 --channels 1-11",
                "wireless activity phy0 --channels 1,6,11 --dwell 500",
            ],
            requires_root=True,
        ),
        Action(
            "wireless.capture.inspect",
            "Inspect 802.11 frames",
            "Open a scrollable, read-only table of captured 802.11 frames "
            "(timestamp, type/subtype, transmitter/receiver/BSSID, SSID). "
            "Navigate with the arrow keys; press Esc, Enter or q to exit.",
            _inspect,
            examples=["wireless capture inspect"],
        ),
        Action(
            "wireless.capture.networks",
            "Show access points",
            "List the access points seen this session (SSID, BSSID, security "
            "(Open/WEP/WPA/WPA2/WPA3), channel, signal, beacon count), built from "
            "captured beacons/probe responses and sorted by beacon count.",
            _networks,
            examples=["wireless capture networks"],
        ),
        Action(
            "wireless.capture.stations",
            "Show client stations",
            "List the client stations seen this session and the AP they talk to, "
            "built from captured data/probe frames and sorted by frame count.",
            _stations,
            examples=["wireless capture stations"],
        ),
        Action(
            "wireless.capture.summary",
            "802.11 capture summary",
            "Show a summary of the wireless session: total frames, unique "
            "BSSIDs/SSIDs, a frame type/subtype breakdown, and filter/capture "
            "state (including whether a channel sweep is stuck on one channel).",
            _summary,
            examples=["wireless capture summary"],
        ),
        Action(
            "wireless.capture.clear",
            "Clear 802.11 frames",
            "Discard all 802.11 frames captured so far this session.",
            _clear,
            examples=["wireless capture clear"],
        ),
        Action(
            "wireless.capture.export",
            "Export 802.11 frames",
            "Export the wireless session's frames to a pcap file (openable in "
            "Wireshark). Relative paths are written under 'exports/'.",
            _export,
            [
                Param("format", "Output format (only 'pcap')"),
                Param("filename", "Destination file path (relative -> exports/)"),
            ],
            ["wireless capture export pcap wifi.pcap"],
        ),
        Action(
            "wireless.capture.import",
            "Import 802.11 frames",
            "Read 802.11 frames from a pcap file and append them to the wireless "
            "session.",
            _import,
            [
                Param("format", "Input format (only 'pcap')"),
                Param("filename", "Source file path"),
            ],
            ["wireless capture import pcap wifi.pcap"],
        ),
        Action(
            "wireless.capture.filter.add",
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
                "wireless capture filter add include --type mgmt --subtype beacon,probe-req",
                "wireless capture filter add include --bssid AA:BB:CC:DD:EE:FF",
                "wireless capture filter add exclude --subtype ack,cts,rts",
            ],
        ),
        Action(
            "wireless.capture.filter.remove",
            "Remove 802.11 filter(s)",
            "Remove wireless filters by id. Accepts a single id, a comma list, a "
            "numeric range, or the keyword 'all'.",
            _filter_remove,
            [Param("ids", "Filter id(s): e.g. 3, 1,4,5, 2-6, or 'all'")],
            [
                "wireless capture filter remove 3",
                "wireless capture filter remove 1,4-6",
                "wireless capture filter remove all",
            ],
        ),
        Action(
            "wireless.capture.filter.show",
            "Show 802.11 filters",
            "List all defined wireless filters with their ids so they can be removed.",
            _filter_show,
            examples=["wireless capture filter show"],
        ),
    ]

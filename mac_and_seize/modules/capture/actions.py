"""Actions exposed by the capture module - a full ``capture`` command group.

Commands: ``start`` / ``stop`` (background capture), ``export``, ``clear``,
``summary``, ``inspect`` and a ``filter`` subgroup (``add`` / ``remove`` /
``show``). Handlers stay thin: they translate parsed values into calls on the
session-scoped :class:`CaptureService` and return plain data for rendering.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mac_and_seize.core.actions import Action, Param
from mac_and_seize.modules.capture.filters import FIELDS
from mac_and_seize.modules.capture.inspect import run_inspector

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.capture.service import CaptureService

SERVICE = "capture"

GROUP_DESCRIPTIONS = {
    "capture": "Capture, filter and inspect packets",
    "capture.filter": "Manage capture include/exclude filters",
}


def _service(context: "AppContext") -> "CaptureService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _start(context: "AppContext", values: dict) -> str:
    return _service(context).start(
        context, time=values.get("time"), count=values.get("count")
    )


def _stop(context: "AppContext", values: dict) -> str:
    service = _service(context)
    added = service.stop()
    return f"Capture stopped: {added} packet(s) added ({len(service.packets)} in session)."


def _export(context: "AppContext", values: dict) -> str:
    path = _service(context).export(values["format"], values["filename"])
    return f"Exported session packets to {path}."


def _import(context: "AppContext", values: dict) -> str:
    service = _service(context)
    added = service.import_file(values["format"], values["filename"])
    return f"Imported {added} packet(s) from {values['filename']} ({len(service.packets)} in session)."


def _clear(context: "AppContext", values: dict) -> str:
    cleared = _service(context).clear()
    return f"Cleared {cleared} packet(s) from the session."


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
        return "No filters defined. Everything is captured."
    return filters


def _summary(context: "AppContext", values: dict) -> dict:
    return _service(context).summary()


def _inspect(context: "AppContext", values: dict) -> None:
    service = _service(context)
    run_inspector(service.inspect_rows())
    return None


def build_actions() -> list[Action]:
    return [
        Action(
            "capture.start",
            "Start capture",
            "Start capturing packets in the background using the current filter "
            "set. The prompt stays usable while it runs; stop it with "
            "'capture stop' (requires root).",
            _start,
            [
                Param("time", "Stop after N seconds (whole capture)", int,
                      required=False),
                Param("count", "Stop after N packets", int, required=False),
            ],
            [
                "capture start",
                "capture start --time 30",
                "capture start --count 100 --time 60",
            ],
            requires_root=True,
        ),
        Action(
            "capture.stop",
            "Stop capture",
            "Stop the running capture and append its packets to the session "
            "(requires root).",
            _stop,
            examples=["capture stop"],
            requires_root=True,
        ),
        Action(
            "capture.export",
            "Export packets",
            "Export the session's captured packets to a file. Only the 'pcap' "
            "format is currently supported. Relative paths are written under the "
            "'exports/' directory; pass an absolute path to write elsewhere.",
            _export,
            [
                Param("format", "Output format (only 'pcap')"),
                Param("filename", "Destination file path (relative -> exports/)"),
            ],
            ["capture export pcap session.pcap", "capture export pcap /tmp/dump.pcap"],
        ),
        Action(
            "capture.import",
            "Import packets",
            "Read packets from a file and append them to the session. Only the "
            "'pcap' format is currently supported.",
            _import,
            [
                Param("format", "Input format (only 'pcap')"),
                Param("filename", "Source file path"),
            ],
            ["capture import pcap session.pcap"],
        ),
        Action(
            "capture.clear",
            "Clear session packets",
            "Discard all packets captured so far this session.",
            _clear,
            examples=["capture clear"],
        ),
        Action(
            "capture.filter.add",
            "Add filter(s)",
            "Add capture filters. Structure: 'add <include|exclude> <fields>'. "
            "Each field value (comma lists / numeric ranges for port) becomes a "
            "separate filter entry with its own id. Include filters are OR'd; an "
            "exclude match always drops the packet.",
            _filter_add,
            [
                Param("action", "include (capture matches) or exclude (drop matches)"),
                Param("interface", "Interface name(s)", required=False),
                Param("source", "Source ip/mac", required=False),
                Param("destination", "Destination ip/mac", required=False),
                Param("protocol", "Protocol (arp, tcp, udp, icmp, ...)", required=False),
                Param("port", "TCP/UDP port(s); list or range", required=False),
            ],
            [
                "capture filter add include --source 127.0.0.1 --protocol tcp,udp,icmp",
                "capture filter add exclude --port 22,80,443",
                "capture filter add include --interface eth0 --port 8000-8010",
            ],
        ),
        Action(
            "capture.filter.remove",
            "Remove filter(s)",
            "Remove filters by id. Accepts a single id, a comma list, a numeric "
            "range, or the keyword 'all'.",
            _filter_remove,
            [Param("ids", "Filter id(s): e.g. 3, 1,4,5, 2-6, or 'all'")],
            ["capture filter remove 3", "capture filter remove 1,4-6", "capture filter remove all"],
        ),
        Action(
            "capture.filter.show",
            "Show filters",
            "List all defined filters with their ids so they can be removed.",
            _filter_show,
            examples=["capture filter show"],
        ),
        Action(
            "capture.summary",
            "Capture summary",
            "Show a summary of the session: total packets, unique hosts, "
            "protocol breakdown and filter/capture state.",
            _summary,
            examples=["capture summary"],
        ),
        Action(
            "capture.inspect",
            "Inspect packets",
            "Open a scrollable, read-only table of captured packets "
            "(timestamp, source, destination, top-level layer). Navigate with "
            "the arrow keys; press Esc, Enter or q to exit.",
            _inspect,
            examples=["capture inspect"],
        ),
    ]

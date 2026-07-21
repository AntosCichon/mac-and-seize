"""Actions exposed by the packet module - the ``packet`` command group.

Commands: ``craft`` and a ``presets`` subgroup (both open the interactive
builder), ``list``, ``send`` (root-only), and ``export`` / ``import`` (pcap or
JSON). Handlers stay thin: they drive the interactive builder via
``context.presenter`` and translate parsed values into calls on the
session-scoped :class:`~mac_and_seize.modules.packet.service.PacketService`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from mac_and_seize.core.actions import Action, Param
from mac_and_seize.core.presenter import BuiltLayer
from mac_and_seize.modules.packet import layers

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext
    from mac_and_seize.modules.packet.service import PacketService

SERVICE = "packet"

GROUP_DESCRIPTIONS = {
    "packet": "Craft, store, send and import/export packets",
    "packet.presets": "Open the builder pre-filled with a common packet",
}


def _service(context: "AppContext") -> "PacketService":
    return context.service(SERVICE)  # type: ignore[return-value]


def _run_builder(
    context: "AppContext", name: str, initial: list[BuiltLayer], title: str
) -> str:
    built = context.presenter.build_packet(layers.CATALOG, initial, title=title)
    if built is None:
        return "Cancelled; no packet saved."
    saved = _service(context).save(name, built)
    return f"Saved packet '{saved}'. Send it with 'packet send {saved}'."


def _craft(context: "AppContext", values: dict) -> str:
    name = values["name"]
    return _run_builder(context, name, [], f"Craft '{name}'")


def _edit(context: "AppContext", values: dict) -> str:
    name = values["name"]
    service = _service(context)
    initial = service.built_layers(name)  # raises if the packet doesn't exist
    built = context.presenter.build_packet(
        layers.CATALOG, initial, title=f"Edit '{name}'"
    )
    if built is None:
        return "Cancelled; packet unchanged."
    updated = service.replace(name, built)
    return f"Updated packet '{updated}'."


def _make_preset_handler(preset: str) -> Callable[["AppContext", dict], str]:
    def handler(context: "AppContext", values: dict) -> str:
        initial = layers.preset_layers(preset)
        return _run_builder(context, values["name"], initial, f"Preset '{preset}'")

    return handler


def _list(context: "AppContext", values: dict):
    packets = _service(context).list_packets()
    if not packets:
        return "No saved packets yet. Craft one with 'packet craft <name>'."
    return packets


def _send(context: "AppContext", values: dict) -> dict:
    return _service(context).send(values["name"], values.get("interface"))


def _export(context: "AppContext", values: dict) -> str:
    path = _service(context).export(values["format"], values["filename"])
    return f"Exported saved packets to {path}."


def _import(context: "AppContext", values: dict) -> str:
    added = _service(context).import_file(values["format"], values["filename"])
    return f"Imported {added} packet(s) from {values['filename']}."


def build_actions() -> list[Action]:
    actions = [
        Action(
            "packet.craft",
            "Craft a packet",
            "Open the interactive builder with no layers. Add layers (Ether, IP, "
            "TCP, ...) and fill their fields, then save the result under the given "
            "name. Nothing is sent - use 'packet send' for that.",
            _craft,
            [Param("name", "Name to save the crafted packet under")],
            ["packet craft my-syn"],
        ),
        Action(
            "packet.edit",
            "Edit a packet",
            "Re-open the interactive builder pre-filled with a saved packet's "
            "layers and values. Saving replaces the packet in place; cancelling "
            "leaves it unchanged.",
            _edit,
            [Param("name", "Name of the saved packet to edit")],
            ["packet edit my-syn"],
        ),
    ]

    for preset in layers.PRESET_NAMES:
        actions.append(
            Action(
                f"packet.presets.{preset}",
                f"Build a {preset} packet",
                f"Open the interactive builder pre-filled with the layers of a "
                f"'{preset}' packet; fill in the remaining fields (addresses, "
                f"ports) and save it under the given name.",
                _make_preset_handler(preset),
                [Param("name", "Name to save the packet under")],
                [f"packet presets {preset} my-{preset}"],
            )
        )

    actions.extend([
        Action(
            "packet.list",
            "List saved packets",
            "List every packet saved this session with its layer chain and a "
            "one-line summary.",
            _list,
            examples=["packet list"],
        ),
        Action(
            "packet.send",
            "Send a packet",
            "Send a saved packet and wait briefly for replies (requires root). "
            "By default scapy chooses the egress interface; pass --interface to "
            "force a specific one.",
            _send,
            [
                Param("name", "Name of the saved packet to send"),
                Param("interface", "Interface to send from (e.g. eth0)",
                      required=False, default=None),
            ],
            ["packet send my-syn", "packet send arp-probe --interface eth0"],
            requires_root=True,
        ),
        Action(
            "packet.export",
            "Export packets",
            "Export all saved packets to a file. 'pcap' writes raw packets (for "
            "Wireshark/interop; names are not stored). 'json' writes a "
            "layer-spec that round-trips names. Relative paths go under "
            "'exports/'; pass an absolute path to write elsewhere.",
            _export,
            [
                Param("format", "Output format (pcap or json)"),
                Param("filename", "Destination file path (relative -> exports/)"),
            ],
            ["packet export json packets.json", "packet export pcap packets.pcap"],
        ),
        Action(
            "packet.import",
            "Import packets",
            "Read packets from a file and add them to the session. 'pcap' packets "
            "are auto-named from the filename; 'json' packets keep their saved "
            "names (deduplicated on collision).",
            _import,
            [
                Param("format", "Input format (pcap or json)"),
                Param("filename", "Source file path"),
            ],
            ["packet import json packets.json", "packet import pcap capture.pcap"],
        ),
    ])
    return actions

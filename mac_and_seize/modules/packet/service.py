"""Craft, store, send and import/export named packets.

The packet module's session-scoped service: it is instantiated once per
:class:`~mac_and_seize.core.context.AppContext` and holds the **session state** -
a name-keyed, insertion-ordered store of crafted :class:`~mac_and_seize.net.Packet`
objects. Packets are built from the interactive builder's layer list (see
:mod:`mac_and_seize.modules.packet.layers`); sending and one-shot pcap I/O are
delegated to the shared scapy adapter.

State lives only for the session (like the capture module); the store is not
persisted across restarts, but can be exported/imported as pcap or JSON.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.core.presenter import BuiltLayer
from mac_and_seize.modules.packet import layers
from mac_and_seize.net import Packet
from mac_and_seize.net.adapters import scapy_io
from mac_and_seize.net.session import DEFAULT_EXPORT_DIR
from mac_and_seize.observability import get_logger

_FORMATS = ("pcap", "json")


class PacketService:
    """Session store of named packets plus craft/send/import/export operations."""

    def __init__(self) -> None:
        self._log = get_logger(__name__)
        self._lock = threading.Lock()
        self.packets: dict[str, Packet] = {}

    # --- Crafting / saving ----------------------------------------------------

    def save(self, name: str, built_layers: list[BuiltLayer]) -> str:
        """Build ``built_layers`` into a packet and store it under ``name``."""
        packet = layers.build_packet(built_layers)
        return self._store(name, packet)

    def _store(self, name: str, packet: Packet) -> str:
        clean = name.strip()
        if not clean:
            raise ValueError("A packet name cannot be empty.")
        with self._lock:
            if clean in self.packets:
                raise ValueError(
                    f"A packet named {clean!r} already exists; choose another name."
                )
            self.packets[clean] = packet
        self._log.info("Saved packet %r (%s)", clean, layers.layer_chain(packet))
        return clean

    def replace(self, name: str, built_layers: list[BuiltLayer]) -> str:
        """Rebuild ``built_layers`` and overwrite the existing packet ``name``.

        Keeps the packet's place in the store. Raises :class:`ModuleError` if no
        packet is saved under ``name``.
        """
        packet = layers.build_packet(built_layers)
        clean = name.strip()
        with self._lock:
            if clean not in self.packets:
                raise ModuleError(f"No saved packet named {clean!r}.")
            self.packets[clean] = packet
        self._log.info("Replaced packet %r (%s)", clean, layers.layer_chain(packet))
        return clean

    def built_layers(self, name: str) -> list[BuiltLayer]:
        """The editable layer list of a saved packet (for re-opening the builder)."""
        return layers.to_built_layers(self.get(name))

    # --- Reading --------------------------------------------------------------

    def get(self, name: str) -> Packet:
        with self._lock:
            packet = self.packets.get(name.strip())
        if packet is None:
            raise ModuleError(f"No saved packet named {name.strip()!r}.")
        return packet

    def list_packets(self) -> list[dict]:
        with self._lock:
            items = list(self.packets.items())
        return [
            {
                "name": name,
                "layers": layers.layer_chain(packet),
                "summary": packet.summary(),
            }
            for name, packet in items
        ]

    # --- Sending --------------------------------------------------------------

    def send(self, name: str, iface: str | None) -> dict:
        """Send the named packet; return a small dict of the send outcome."""
        packet = self.get(name)
        if iface is not None:
            iface = iface.strip()
            available = scapy_io.available_interfaces()
            if iface not in available:
                raise ValueError(
                    f"Unknown interface {iface!r}. Available: {', '.join(available) or 'none'}."
                )
        try:
            answered, unanswered = scapy_io.send(iface, packet)
        except OSError as exc:
            raise ModuleError(f"Could not send packet: {exc.strerror or exc}.") from exc
        self._log.info(
            "Sent packet %r on %s (%d answered)", name, iface or "default", len(answered)
        )
        return {
            "packet": name.strip(),
            "interface": iface or "default",
            "answered": len(answered),
            "unanswered": len(unanswered),
        }

    # --- Import / export ------------------------------------------------------

    @staticmethod
    def _check_format(fmt: str) -> str:
        normalized = fmt.lower().lstrip(".")
        if normalized not in _FORMATS:
            raise ModuleError(
                f"Unsupported format {fmt!r}; use one of: {', '.join(_FORMATS)}."
            )
        return normalized

    @staticmethod
    def _resolve(filename: str) -> Path:
        path = Path(filename)
        return path if path.is_absolute() else DEFAULT_EXPORT_DIR / path

    def export(self, fmt: str, filename: str) -> Path:
        normalized = self._check_format(fmt)
        path = self._resolve(filename)
        with self._lock:
            if not self.packets:
                raise ModuleError("No saved packets to export; craft one first.")
            named = list(self.packets.items())
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if normalized == "pcap":
                scapy_io.write_pcap(str(path), [pkt for _, pkt in named], append=False)
            else:
                document = [
                    {"name": name, "layers": layers.to_spec(pkt)} for name, pkt in named
                ]
                path.write_text(json.dumps(document, indent=2))
        except OSError as exc:
            raise ModuleError(f"Could not write to {path}: {exc.strerror or exc}.") from exc
        self._log.info("Exported %d packet(s) to %s", len(named), path)
        return path

    def import_file(self, fmt: str, filename: str) -> int:
        normalized = self._check_format(fmt)
        path = Path(filename)
        if not path.is_file():
            raise ModuleError(f"File not found: {filename}.")
        if normalized == "pcap":
            imported = self._import_pcap(path)
        else:
            imported = self._import_json(path)
        self._log.info("Imported %d packet(s) from %s", imported, path)
        return imported

    def _import_pcap(self, path: Path) -> int:
        try:
            packets = scapy_io.read_pcap(str(path))
        except Exception as exc:  # noqa: BLE001 - surface any read/parse failure cleanly
            raise ModuleError(f"Could not read {path}: {exc}") from exc
        stem = path.stem or "packet"
        for index, packet in enumerate(packets, start=1):
            self._store(self._unique_name(f"{stem}-{index}"), packet)
        return len(packets)

    def _import_json(self, path: Path) -> int:
        try:
            document = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise ModuleError(f"Could not read {path}: {exc}") from exc
        if not isinstance(document, list):
            raise ModuleError("Invalid packet JSON: expected a list of packets.")
        count = 0
        for entry in document:
            if not isinstance(entry, dict) or "layers" not in entry:
                raise ModuleError("Invalid packet JSON: each entry needs a 'layers' list.")
            packet = layers.from_spec(entry["layers"])
            name = self._unique_name(str(entry.get("name") or "packet"))
            self._store(name, packet)
            count += 1
        return count

    def _unique_name(self, base: str) -> str:
        """A name based on ``base`` that isn't already taken (``base``, ``base-2``...)."""
        base = base.strip() or "packet"
        with self._lock:
            existing = set(self.packets)
        if base not in existing:
            return base
        suffix = 2
        while f"{base}-{suffix}" in existing:
            suffix += 1
        return f"{base}-{suffix}"

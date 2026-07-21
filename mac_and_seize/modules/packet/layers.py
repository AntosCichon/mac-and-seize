"""Layer catalog, presets, and (de)serialization for the packet builder.

This is the packet module's own vocabulary for the interactive builder: which
protocol layers a user may stack, which fields each exposes, and how to turn the
front-end's :class:`~mac_and_seize.core.presenter.BuiltLayer` list into a real
:class:`~mac_and_seize.net.Packet` (and back, for JSON import/export).

It imports scapy layer classes directly - that is allowed *inside* a module; the
shared :class:`~mac_and_seize.net.Packet` wrapper is what leaves the module.
"""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import NoPayload, Raw

from mac_and_seize.core.presenter import BuiltLayer, LayerField, LayerType
from mac_and_seize.net import Packet

# The layer types the builder offers, in a sensible stacking order. Each field's
# ``type`` (str/int) drives conversion when composing the packet; an empty value
# means "leave it to scapy's protocol default".
CATALOG: list[LayerType] = [
    LayerType("Ether", [
        LayerField("src", "Source MAC", help="e.g. 00:11:22:33:44:55"),
        LayerField("dst", "Dest MAC", help="e.g. ff:ff:ff:ff:ff:ff for broadcast"),
        LayerField("type", "EtherType", help="Numeric; usually left blank (auto)", type=int),
    ]),
    LayerType("Dot1Q", [
        LayerField("vlan", "VLAN id", help="802.1Q VLAN id (0-4095)", type=int),
        LayerField("prio", "Priority", help="802.1p priority (0-7)", type=int),
    ]),
    LayerType("ARP", [
        LayerField("op", "Operation", default="1", help="1=request, 2=reply", type=int),
        LayerField("hwsrc", "Sender MAC", help="Sender hardware address"),
        LayerField("psrc", "Sender IP", help="Sender protocol address"),
        LayerField("hwdst", "Target MAC", help="Target hardware address"),
        LayerField("pdst", "Target IP", help="Target protocol address"),
    ]),
    LayerType("IP", [
        LayerField("src", "Source IP", help="e.g. 192.168.1.10"),
        LayerField("dst", "Dest IP", help="e.g. 192.168.1.1"),
        LayerField("ttl", "TTL", help="Time to live (1-255)", type=int),
    ]),
    LayerType("IPv6", [
        LayerField("src", "Source IPv6", help="e.g. fe80::1"),
        LayerField("dst", "Dest IPv6", help="e.g. fe80::2"),
        LayerField("hlim", "Hop limit", help="Hop limit (1-255)", type=int),
    ]),
    LayerType("ICMP", [
        LayerField("type", "Type", default="8", help="8=echo request, 0=echo reply", type=int),
        LayerField("code", "Code", help="ICMP code", type=int),
    ]),
    LayerType("TCP", [
        LayerField("sport", "Source port", help="0-65535", type=int),
        LayerField("dport", "Dest port", help="0-65535", type=int),
        LayerField("flags", "Flags", help="e.g. S, SA, FPU"),
        LayerField("seq", "Sequence", help="Sequence number", type=int),
        LayerField("ack", "Ack", help="Acknowledgement number", type=int),
    ]),
    LayerType("UDP", [
        LayerField("sport", "Source port", help="0-65535", type=int),
        LayerField("dport", "Dest port", help="0-65535", type=int),
    ]),
    LayerType("Raw", [
        LayerField("load", "Payload", help="Raw payload text"),
    ]),
]

_SCAPY_BY_NAME = {
    "Ether": Ether, "Dot1Q": Dot1Q, "ARP": ARP, "IP": IP, "IPv6": IPv6,
    "ICMP": ICMP, "TCP": TCP, "UDP": UDP, "Raw": Raw,
}

_FIELDS_BY_NAME: dict[str, dict[str, LayerField]] = {
    layer.name: {field.key: field for field in layer.fields} for layer in CATALOG
}

# Presets: layers pre-added with the protocol-defining fields filled in, leaving
# addresses/ports for the user. Values only carry the pre-set fields; every other
# catalog field shows as "(default)" in the builder until the user fills it.
_PRESETS: dict[str, list[BuiltLayer]] = {
    "ping": [BuiltLayer("Ether", {}), BuiltLayer("IP", {}), BuiltLayer("ICMP", {"type": "8"})],
    "arp": [BuiltLayer("Ether", {"dst": "ff:ff:ff:ff:ff:ff"}), BuiltLayer("ARP", {"op": "1"})],
    "arp-reply": [BuiltLayer("Ether", {}), BuiltLayer("ARP", {"op": "2"})],
    "tcp-syn": [BuiltLayer("Ether", {}), BuiltLayer("IP", {}), BuiltLayer("TCP", {"flags": "S", "dport": "80"})],
    "udp": [BuiltLayer("Ether", {}), BuiltLayer("IP", {}), BuiltLayer("UDP", {"dport": "53"})],
}

PRESET_NAMES = list(_PRESETS)


def preset_layers(name: str) -> list[BuiltLayer]:
    """Fresh (copied) initial layers for preset ``name`` (raises if unknown)."""
    try:
        template = _PRESETS[name]
    except KeyError:
        raise ValueError(f"Unknown preset {name!r}.") from None
    return [BuiltLayer(layer.name, dict(layer.values)) for layer in template]


def _to_int(key: str, raw: str) -> int:
    try:
        return int(raw, 0)  # base 0 -> accept decimal and 0x.. hex
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{key!r} must be an integer (got {raw!r}).") from exc


def _instantiate(name: str, values: dict[str, str]):
    """Build one scapy layer from catalog ``values`` (empty fields omitted)."""
    fields = _FIELDS_BY_NAME[name]
    kwargs: dict = {}
    for key, raw in values.items():
        if raw is None or raw == "":
            continue
        field = fields.get(key)
        if field is None:
            continue  # not a catalog field for this layer; ignore
        kwargs[key] = _to_int(key, raw) if field.type is int else raw
    return _SCAPY_BY_NAME[name](**kwargs)


def build_packet(built_layers: list[BuiltLayer]) -> Packet:
    """Compose an ordered :class:`BuiltLayer` list into a :class:`Packet`.

    Only fields the user filled are set; the rest use scapy's protocol defaults.
    Raises :class:`ValueError` on an unknown layer or a bad field value.
    """
    if not built_layers:
        raise ValueError("Add at least one layer before saving the packet.")
    stack = None
    for layer in built_layers:
        if layer.name not in _SCAPY_BY_NAME:
            raise ValueError(f"Unknown layer {layer.name!r}.")
        try:
            scapy_layer = _instantiate(layer.name, layer.values)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid value in {layer.name} layer: {exc}") from exc
        stack = scapy_layer if stack is None else stack / scapy_layer
    return Packet(stack)


def layer_chain(packet: Packet) -> str:
    """Slash-joined layer names of ``packet`` (e.g. ``Ether/IP/ICMP``)."""
    names: list[str] = []
    current = packet.build()
    while current is not None and not isinstance(current, NoPayload):
        names.append(current.__class__.__name__)
        current = current.payload
    return "/".join(names) or "-"


def _value_to_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")  # round-trips 1:1 through latin-1
    return str(value)


def to_spec(packet: Packet) -> list[dict]:
    """Serialize ``packet`` to a JSON-friendly ordered list of layer specs.

    Each entry is ``{"layer": <class name>, "fields": {<set fields as text>}}``.
    Only the fields scapy has explicitly set are recorded (defaults are omitted).
    """
    spec: list[dict] = []
    current = packet.build()
    while current is not None and not isinstance(current, NoPayload):
        fields = {key: _value_to_text(value) for key, value in current.fields.items()}
        spec.append({"layer": current.__class__.__name__, "fields": fields})
        current = current.payload
    return spec


def to_built_layers(packet: Packet) -> list[BuiltLayer]:
    """Reconstruct editable :class:`BuiltLayer`s from ``packet`` for the builder.

    Mirrors :func:`to_spec` but keeps only the fields the builder can edit (the
    catalog fields for each layer), so re-opening a crafted packet shows exactly
    the values the user set. Layers outside the catalog keep their raw fields.
    """
    result: list[BuiltLayer] = []
    for entry in to_spec(packet):
        name = entry["layer"]
        fields = entry["fields"]
        catalog_fields = _FIELDS_BY_NAME.get(name)
        if catalog_fields is not None:
            values = {key: value for key, value in fields.items() if key in catalog_fields}
        else:
            values = dict(fields)
        result.append(BuiltLayer(name, values))
    return result


def _coerce(layer_name: str, key: str, raw: str):
    """Convert a JSON field value back to the type scapy expects for it."""
    field = _FIELDS_BY_NAME.get(layer_name, {}).get(key)
    if field is not None:
        return _to_int(key, raw) if field.type is int else raw
    # Field outside our catalog (e.g. an auto EtherType scapy had set): best
    # effort - numeric when it parses, otherwise the raw string.
    try:
        return int(raw, 0)
    except (ValueError, TypeError):
        return raw


def from_spec(spec: list[dict]) -> Packet:
    """Rebuild a :class:`Packet` from a :func:`to_spec` layer list.

    Raises :class:`ValueError` on an empty spec, an unknown layer name, or a
    field value that scapy rejects.
    """
    if not spec:
        raise ValueError("Empty packet spec.")
    stack = None
    for entry in spec:
        name = entry.get("layer")
        scapy_cls = _SCAPY_BY_NAME.get(name)
        if scapy_cls is None:
            raise ValueError(f"Unknown layer {name!r} in packet spec.")
        kwargs = {key: _coerce(name, key, raw) for key, raw in (entry.get("fields") or {}).items()}
        try:
            scapy_layer = scapy_cls(**kwargs)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid {name} field: {exc}") from exc
        stack = scapy_layer if stack is None else stack / scapy_layer
    return Packet(stack)

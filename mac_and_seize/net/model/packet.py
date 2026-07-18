"""A thin, ergonomic wrapper around scapy packets.

The :class:`Packet` domain type represents a single network packet: constructing
one (the ARP/ICMP/TCP/UDP factories), inspecting its layers, and rendering it for
display. It performs no network I/O - sending, sniffing, and reading/writing pcap
files live in the scapy adapter (``net.adapters.scapy_io``).
"""

from __future__ import annotations

from datetime import datetime

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
from scapy.layers.l2 import ARP, Dot1Q, Ether  # noqa: F401 (Dot1Q re-exported)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

_IGNORED_LAYERS = {"Raw", "Padding", "NoPayload"}

# 802.11 frame type / subtype -> short human names, used by :meth:`Packet.dot11_info`
# and the wireless capture views. Subtypes are keyed by ``(type, subtype)`` because
# subtype numbers are only unique within a type.
_DOT11_TYPE_NAMES = {0: "mgmt", 1: "ctrl", 2: "data", 3: "ext"}
_DOT11_SUBTYPE_NAMES = {
    (0, 0): "assoc-req", (0, 1): "assoc-resp", (0, 2): "reassoc-req",
    (0, 3): "reassoc-resp", (0, 4): "probe-req", (0, 5): "probe-resp",
    (0, 8): "beacon", (0, 9): "atim", (0, 10): "disassoc", (0, 11): "auth",
    (0, 12): "deauth", (0, 13): "action",
    (1, 8): "bar", (1, 9): "ba", (1, 10): "ps-poll", (1, 11): "rts",
    (1, 12): "cts", (1, 13): "ack", (1, 14): "cf-end", (1, 15): "cf-end-ack",
    (2, 0): "data", (2, 4): "null", (2, 8): "qos-data", (2, 12): "qos-null",
}


def _norm_mac(value) -> str | None:
    """Lower-cased MAC string, or ``None`` for a missing/absent address."""
    return str(value).lower() if value else None


def _dot11_ssid(pkt) -> str | None:
    """Extract the SSID from an 802.11 frame's information elements.

    Only management frames that carry an SSID element (beacon, probe req/resp,
    (re)assoc req) have one. An empty SSID element means a hidden network; frames
    without the element return ``None``.
    """
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:  # 0 == SSID element
            try:
                return elt.info.decode(errors="replace") or "<hidden>"
            except Exception:  # noqa: BLE001 - a malformed element must not raise
                return None
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def _dot11_channel(pkt) -> int | None:
    """Advertised channel from the DS Parameter Set element (ID 3).

    Present in beacons and probe responses; it is the network's operating
    channel regardless of which channel we were tuned to when we heard it.
    """
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 3 and elt.info:
            try:
                return int(elt.info[0])
            except (TypeError, ValueError, IndexError):
                return None
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def _radiotap_signal(pkt) -> int | None:
    """Antenna signal in dBm from the RadioTap header, or ``None`` if absent."""
    rt = pkt.getlayer(RadioTap)
    if rt is None:
        return None
    value = getattr(rt, "dBm_AntSignal", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _rsn_akm_suites(info: bytes) -> set[int]:
    """AKM suite type numbers from an RSN (ID 48) information-element body.

    The suite type is the last byte of each 4-byte ``00-0F-AC-XX`` selector; it
    tells WPA3 (SAE = 8) apart from WPA2 (PSK = 2, 802.1X = 1, ...). Returns an
    empty set if the element is truncated or malformed.
    """
    try:
        i = 2 + 4  # skip version (2 bytes) + group cipher suite (4 bytes)
        pair_count = int.from_bytes(info[i:i + 2], "little")
        i += 2 + 4 * pair_count  # skip the pairwise cipher suite list
        akm_count = int.from_bytes(info[i:i + 2], "little")
        i += 2
        suites: set[int] = set()
        for _ in range(akm_count):
            selector = info[i:i + 4]
            i += 4
            if len(selector) == 4:
                suites.add(selector[3])
        return suites
    except Exception:  # noqa: BLE001 - a truncated element must not raise
        return set()


def _dot11_security(pkt) -> str | None:
    """Security of a beacon/probe response: Open/WEP/WPA/WPA2/WPA3 (or mixed).

    Combines the Privacy capability bit with the RSN (ID 48) and WPA vendor
    (ID 221, Microsoft OUI) information elements: RSN AKM suites distinguish WPA3
    (SAE) from WPA2, and transition modes read as e.g. ``WPA2/WPA3``. Returns
    ``None`` for a frame without a capability field (not a beacon/probe response).
    """
    body = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
    if body is None:
        return None
    privacy = bool(getattr(body.cap, "privacy", False))

    has_rsn = has_wpa = False
    akms: set[int] = set()
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        try:
            info = bytes(elt.info) if elt.info else b""
            if elt.ID == 48:  # RSN element -> WPA2/WPA3
                has_rsn = True
                akms |= _rsn_akm_suites(info)
            elif elt.ID == 221 and info[:4] == b"\x00\x50\xf2\x01":  # WPA1 (MS OUI)
                has_wpa = True
        except Exception:  # noqa: BLE001 - one bad element must not abort the scan
            pass
        elt = elt.payload.getlayer(Dot11Elt)

    if has_rsn:
        wpa3 = bool(akms & {8, 9})               # SAE, FT-SAE
        wpa2 = bool(akms & {1, 2, 3, 4, 5, 6}) or not akms
        label = "WPA2/WPA3" if wpa3 and wpa2 else "WPA3" if wpa3 else "WPA2"
        return f"WPA/{label}" if has_wpa else label
    if has_wpa:
        return "WPA"
    return "WEP" if privacy else "Open"


class Packet:
    """Wrapper class for scapy packets.

    Examples
    --------
    ARP request::

        pkt = Packet.arp_request(src_mac="00:11:22:33:44:55",
                                 src_ip="192.168.1.1", dst_ip="192.168.1.2")

    TCP packet with custom flags (URG, PSH, FIN)::

        pkt = Packet.tcp(src_mac="00:11:22:33:44:55", src_ip="192.168.1.1",
                         dst_mac="66:77:88:99:AA:BB", dst_ip="192.168.1.2",
                         src_port=12345, dst_port=80, flags="UPF")

    Tag an existing packet with a VLAN::

        pkt = Packet(...).add_layer(Dot1Q(vlan=100))
    """

    def __init__(self, pkt=None):
        self._pkt = pkt if pkt is not None else Ether()

    @classmethod
    def from_scapy(cls, pkt) -> "Packet":
        return cls(pkt)

    # --- Factories ---

    @classmethod
    def arp_request(cls, src_mac: str, src_ip: str, dst_ip: str) -> "Packet":
        return cls(
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(hwsrc=src_mac, psrc=src_ip, pdst=dst_ip, op=1)
        )

    @classmethod
    def arp_reply(
        cls, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str
    ) -> "Packet":
        return cls(
            Ether(src=src_mac, dst=dst_mac)
            / ARP(hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip, op=2)
        )

    @classmethod
    def ping(
        cls, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str, **icmp_kwargs
    ) -> "Packet":
        return cls(
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / ICMP(type=8, **icmp_kwargs)
        )

    @classmethod
    def tcp(
        cls,
        src_mac: str,
        src_ip: str,
        dst_mac: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        data: bytes | str = b"",
        **tcp_kwargs,
    ) -> "Packet":
        payload = data.encode() if isinstance(data, str) else data
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, **tcp_kwargs)
        )
        if payload:
            pkt /= Raw(load=payload)
        return cls(pkt)

    @classmethod
    def udp(
        cls,
        src_mac: str,
        src_ip: str,
        dst_mac: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        data: bytes | str = b"",
        **udp_kwargs,
    ) -> "Packet":
        payload = data.encode() if isinstance(data, str) else data
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=src_port, dport=dst_port, **udp_kwargs)
        )
        if payload:
            pkt /= Raw(load=payload)
        return cls(pkt)

    # --- Layer access & manipulation ---

    def layer(self, layer_class):
        return self._pkt.getlayer(layer_class)

    def has_layer(self, layer_class) -> bool:
        return self._pkt.haslayer(layer_class) != 0

    def add_layer(self, layer) -> "Packet":
        self._pkt /= layer
        return self

    def set_payload(self, data: bytes | str) -> "Packet":
        payload = data.encode() if isinstance(data, str) else data
        if self._pkt.haslayer(Raw):
            self._pkt.getlayer(Raw).load = payload
        else:
            self._pkt /= Raw(load=payload)
        return self

    # --- Build / pcap ---

    def build(self):
        return self._pkt

    def pcap(self):
        return self._pkt

    # --- Human-readable output ---

    def summary(self) -> str:
        return self._pkt.summary()

    def show(self) -> str | None:
        return self._pkt.show(dump=True)

    def info(self) -> dict:
        result: dict = {}
        if self._pkt.haslayer(Ether):
            eth = self._pkt[Ether]
            result["src_mac"] = eth.src
            result["dst_mac"] = eth.dst
        if self._pkt.haslayer(Dot11):
            dot11 = self._pkt[Dot11]
            # 802.11 addressing: addr2 = transmitter (src), addr1 = receiver
            # (dst), addr3 = BSSID. There is no Ether layer here, so this fills
            # the src/dst the generic views expect.
            result.setdefault("src_mac", dot11.addr2)
            result.setdefault("dst_mac", dot11.addr1)
            if dot11.addr3:
                result["bssid"] = dot11.addr3
        if self._pkt.haslayer(IP):
            ip = self._pkt[IP]
            result["src_ip"] = ip.src
            result["dst_ip"] = ip.dst
            result["ttl"] = ip.ttl
        elif self._pkt.haslayer(IPv6):
            ip6 = self._pkt[IPv6]
            result["src_ip"] = ip6.src
            result["dst_ip"] = ip6.dst
        if self._pkt.haslayer(TCP):
            tcp = self._pkt[TCP]
            result["src_port"] = tcp.sport
            result["dst_port"] = tcp.dport
            result["flags"] = str(tcp.flags)
            result["seq"] = tcp.seq
            result["ack"] = tcp.ack
        elif self._pkt.haslayer(UDP):
            udp = self._pkt[UDP]
            result["src_port"] = udp.sport
            result["dst_port"] = udp.dport
        elif self._pkt.haslayer(ICMP):
            icmp = self._pkt[ICMP]
            result["icmp_type"] = icmp.type
            result["icmp_code"] = icmp.code
        elif self._pkt.haslayer(ARP):
            arp = self._pkt[ARP]
            result["arp_op"] = "request" if arp.op == 1 else "reply"
            result["src_ip"] = arp.psrc
            result["dst_ip"] = arp.pdst
        if self._pkt.haslayer(Raw):
            result["payload"] = bytes(self._pkt[Raw].load)
        return result

    def is_dot11(self) -> bool:
        """Whether this is an 802.11 (Wi-Fi) frame, as seen in monitor mode."""
        return self._pkt.haslayer(Dot11)

    def dot11_info(self) -> dict:
        """802.11 view of the frame, or ``{}`` for a non-802.11 packet.

        Keys: ``type`` (mgmt/ctrl/data), ``subtype`` (beacon/probe-req/deauth/
        ...), ``transmitter``/``receiver``/``bssid`` (the addr2/addr1/addr3
        MACs), ``ssid`` (management frames only), ``channel``, ``signal`` (dBm
        from the RadioTap header, when present), and ``security``
        (Open/WEP/WPA/WPA2/WPA3, beacons/probe responses only).
        """
        dot11 = self._pkt.getlayer(Dot11)
        if dot11 is None:
            return {}
        try:
            type_num = int(dot11.type)
            subtype_num = int(dot11.subtype)
        except (TypeError, ValueError):
            type_num = subtype_num = -1
        return {
            "type": _DOT11_TYPE_NAMES.get(type_num, str(type_num)),
            "subtype": _DOT11_SUBTYPE_NAMES.get((type_num, subtype_num), str(subtype_num)),
            "receiver": _norm_mac(dot11.addr1),
            "transmitter": _norm_mac(dot11.addr2),
            "bssid": _norm_mac(dot11.addr3),
            "ssid": _dot11_ssid(self._pkt),
            "channel": _dot11_channel(self._pkt),
            "signal": _radiotap_signal(self._pkt),
            "security": _dot11_security(self._pkt),
        }

    def timestamp(self) -> str:
        """Capture time as ``HH:MM:SS`` (``-`` if scapy did not record one)."""
        epoch = getattr(self._pkt, "time", None)
        if not epoch:
            return "-"
        return datetime.fromtimestamp(float(epoch)).strftime("%H:%M:%S")

    def top_layer(self) -> str:
        """Name of the outermost meaningful protocol layer (skips Raw/Padding)."""
        name = "-"
        for layer in self._pkt.layers():
            candidate = layer.__name__
            if candidate not in _IGNORED_LAYERS:
                name = candidate
        return name

    def inspect_row(self) -> dict:
        """Compact one-line view for the ``inspect`` table.

        Columns: timestamp, capture interface, source and destination each as
        ``mac / ip / port`` (missing parts shown as ``-``), and the top-level
        protocol layer.
        """
        info = self.info()

        def part(key: str) -> str:
            value = info.get(key)
            return "-" if value in (None, "") else str(value)

        def endpoint(prefix: str) -> str:
            return f"{part(prefix + '_mac')} / {part(prefix + '_ip')} / {part(prefix + '_port')}"

        sniffed_on = getattr(self._pkt, "sniffed_on", None)
        return {
            "timestamp": self.timestamp(),
            "interface": sniffed_on if sniffed_on else "-",
            "source": endpoint("src"),
            "destination": endpoint("dst"),
            "layer": self.top_layer(),
        }

    def __repr__(self) -> str:
        return f"Packet({self._pkt.summary()})"

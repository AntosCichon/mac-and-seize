"""A thin, ergonomic wrapper around scapy packets (capture module)."""

from __future__ import annotations

from datetime import datetime

from scapy.layers.l2 import ARP, Dot1Q, Ether  # noqa: F401 (Dot1Q re-exported)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap

_IGNORED_LAYERS = {"Raw", "Padding", "NoPayload"}


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


def write_pcap(filename: str, packets: list, append: bool = True) -> None:
    wrpcap(
        filename,
        [p.pcap() if isinstance(p, Packet) else p for p in packets],
        append=append,
    )


def read_pcap(filename: str) -> list["Packet"]:
    """Read a pcap file, returning wrapped :class:`Packet`s."""
    return [Packet.from_scapy(pkt) for pkt in rdpcap(filename)]

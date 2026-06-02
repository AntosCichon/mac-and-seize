from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import wrpcap
import io
from contextlib import redirect_stdout


class Packet:

    """
    Wrapper class for scapy packets, example usage:

    1. ARP request:
        pkt = Packet.arp_request(src_mac="00:11:22:33:44:55", src_ip="192.168.1.1", dst_ip="192.168.1.2")

    2. TCP packet with custom flags (URG, PSH, FIN):
        pkt = Packet.tcp(src_mac="00:11:22:33:44:55", src_ip="192.168.1.1", dst_mac="66:77:88:99:AA:BB", dst_ip="192.168.1.2", src_port=12345, dst_port=80, flags="UPF")

    3. Tag existing packet with VLAN:
        pkt = Packet(...).add_layer(Dot1Q(vlan=100))
    """

    def __init__(self, pkt=None):
        self._pkt = pkt if pkt is not None else Ether()

    @classmethod
    def from_scapy(cls, pkt):
        return cls(pkt)

    # --- Factories ---

    @classmethod
    def arp_request(cls, src_mac: str, src_ip: str, dst_ip: str):
        return cls(
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(hwsrc=src_mac, psrc=src_ip, pdst=dst_ip, op=1)
        )

    @classmethod
    def arp_reply(cls, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str):
        return cls(
            Ether(src=src_mac, dst=dst_mac) /
            ARP(hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip, op=2)
        )

    @classmethod
    def ping(cls, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str, **icmp_kwargs):
        return cls(
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            ICMP(type=8, **icmp_kwargs)
        )

    @classmethod
    def tcp(cls, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str,
            src_port: int, dst_port: int, data: bytes | str = b"", **tcp_kwargs):
        payload = data.encode() if isinstance(data, str) else data
        pkt = (
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=src_port, dport=dst_port, **tcp_kwargs)
        )
        if payload:
            pkt /= Raw(load=payload)
        return cls(pkt)

    @classmethod
    def udp(cls, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str,
            src_port: int, dst_port: int, data: bytes | str = b"", **udp_kwargs):
        payload = data.encode() if isinstance(data, str) else data
        pkt = (
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=src_port, dport=dst_port, **udp_kwargs)
        )
        if payload:
            pkt /= Raw(load=payload)
        return cls(pkt)

    # --- Layer access & manipulation ---

    def layer(self, layer_class):
        return self._pkt.getlayer(layer_class)

    def has_layer(self, layer_class) -> bool:
        return self._pkt.haslayer(layer_class) != 0

    def add_layer(self, layer):
        self._pkt /= layer
        return self

    def set_payload(self, data: bytes | str):
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
        result = {}
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

    def __repr__(self):
        return f"Packet({self._pkt.summary()})"


def write_pcap(filename: str, packets: list, append: bool = True):
    wrpcap(filename, [p.pcap() if isinstance(p, Packet) else p for p in packets], append=append)
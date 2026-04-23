from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

class L2Packet:
    def __init__(self, src_mac: str, dst_mac: str, data: bytes | str = b""):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.layers = [Ether(src = src_mac, dst = dst_mac)]
        self.payload = data.encode() if isinstance(data, str) else data
        
    def add_layer(self, layer):
        self.layers.append(layer)
        return self
    
    def build(self):
        packet = self.layers[0]
        for layer in self.layers[1:]:
            packet /= layer
        if self.payload:
            packet /= Raw(load = self.payload)
        return packet

    def arp(self, src_ip: str, dst_ip: str, op: int = 1):
        return self.add_layer(ARP(hwsrc = self.src_mac, psrc = src_ip, pdst = dst_ip, hwdst = "ff:ff:ff:ff:ff:ff", op = op))

    def vlan(self, vlan_id: int, priority: int = 0):
        return self.add_layer(Dot1Q(vlan = vlan_id, prio = priority))

class L3Packet(L2Packet):
    def __init__(self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str):
        super().__init__(src_mac, dst_mac)
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def ipv4(self, **kwargs):
        return self.add_layer(IP(src = self.src_ip, dst = self.dst_ip, **kwargs))
    
    def ipv6(self, **kwargs):
        return self.add_layer(IPv6(src = self.src_ip, dst = self.dst_ip, **kwargs))

    def icmp(self, **kwargs):
        return self.add_layer(ICMP(**kwargs))

class L4Packet(L3Packet):
    def __init__(self, src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        super().__init__(src_mac, dst_mac, src_ip, dst_ip)
        self.src_port = src_port
        self.dst_port = dst_port

    def tcp(self, **kwargs):
        return self.add_layer(TCP(sport = self.src_port, dport = self.dst_port, **kwargs))

    def udp(self, **kwargs):
        return self.add_layer(UDP(sport = self.src_port, dport = self.dst_port, **kwargs))
    
class ArpRequest(L2Packet):
    def __init__(self, src_mac: str, src_ip: str, dst_ip: str):
        super().__init__(src_mac, "ff:ff:ff:ff:ff:ff")
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.arp(src_ip, dst_ip)

class PingRequest(L3Packet):
    def __init__(self, src_mac: str, src_ip: str, dst_mac: str, dst_ip: str):
        super().__init__(src_mac, dst_mac, src_ip, dst_ip)
        self.icmp(type = 8)
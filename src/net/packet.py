from scapy.all import Ether, ARP, Dot1Q, IP, IPv6, ICMP, TCP, UDP, Raw

class PacketBuilder:
    def __init__(self):
        self.layers = []

    def add(self, layer):
        self.layers.append(layer)
        return self
    
    # Data link methods
    def ethernet(self, **kwargs):
        return self.add(Ether(**kwargs))
    
    def arp(self, **kwargs):
        return self.add(ARP(**kwargs))
    
    def vlan(self, **kwargs):
        return self.add(Dot1Q(**kwargs))
    
    # Network layer methods
    def ipv4(self, **kwargs):
        return self.add(IP(**kwargs))
    
    def ipv6(self, **kwargs):
        return self.add(IPv6(**kwargs))
    
    def icmp(self, **kwargs):
        return self.add(ICMP(**kwargs))
    
    # Transport layer methods
    def tcp(self, **kwargs):
        return self.add(TCP(**kwargs))
    
    def udp(self, **kwargs):
        return self.add(UDP(**kwargs))
    
    # Payload
    def payload(self, data: bytes | str):
        if isinstance(data, str):
            data = data.encode()
        return self.add(Raw(load = data))
    
    def build(self):
        if not self.layers:
            raise ValueError("No layers added to the packet.")
        packet = self.layers[0]
        for layer in self.layers[1:]:
            packet /= layer
        return packet
    

    
def arp_request(src_mac, src_ip, dst_ip):
    return (
        PacketBuilder()
        .ethernet(dst = "ff:ff:ff:ff:ff:ff", src = src_mac)
        .arp(op = 1, hwsrc = src_mac, psrc = src_ip, pdst = dst_ip, hwdst = "ff:ff:ff:ff:ff:ff")
        .build()
    )

def ping_request(src_mac, src_ip, dst_mac, dst_ip):
    return (
        PacketBuilder()
        .ethernet(dst = dst_mac, src = src_mac)
        .ipv4(src = src_ip, dst = dst_ip)
        .icmp(type = 8)
        .build()
    )
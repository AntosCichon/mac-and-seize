import netifaces as ni
from src.util.logging import LogMessage
from scapy.all import sendp, srp
import threading

def get_interfaces():
    return ni.interfaces()

iface_id: int | None = None
def assign_id():
    global iface_id
    if iface_id is None:
        iface_id = 0
    else:
        iface_id += 1
    return iface_id


class Interface:
    def __init__(self, name: str):
        if name not in get_interfaces():
            raise ValueError(f"Interface '{name}' does not exist.")
        self.name = name
        self.id = assign_id()
        self.system_path = f"/sys/class/net/{name}/"
        self.state = self.get_state()
        self.ipv4 = {
            "addr": list(),
            "netmask": list(),
            "broadcast": list(),
            "peer": list(),
            "count": 0
        }
        self.ipv6 = {
            "addr": list(),
            "netmask": list(),
            "broadcast": list(),
            "peer": list(),
            "count": 0
        }
        self.mac = {
            "addr": list(),
            "peer": list(),
            "count": 0
        }

        self.get_ipv4()
        self.get_ipv6()
        self.get_mac()

        LogMessage(f"Initialized new interface: {self.name} (id: {self.id})")

    def get_state(self):
        with open(f"{self.system_path}operstate", "r") as f:
            state = f.read()
        return state

    def get_ipv4(self, address_type = None) -> list | dict:
        if ni.AF_INET not in ni.ifaddresses(self.name):
            self.ipv4["count"] = 0
            return self.ipv4[address_type] if address_type is not None else self.ipv4
        info = ni.ifaddresses(self.name)[ni.AF_INET]
        self.ipv4["count"] = len(info)
        for address in [ address_type ] if address_type is not None else [ "addr", "netmask", "broadcast", "peer" ]:
            self.ipv4[address] = [ info[i][address] if address in info[i] else None for i in range(self.ipv4["count"]) ]
        return self.ipv4[address_type] if address_type is not None else self.ipv4
    
    def get_ipv6(self, address_type = None) -> list | dict:
        if ni.AF_INET6 not in ni.ifaddresses(self.name):
            self.ipv6["count"] = 0
            return self.ipv6[address_type] if address_type is not None else self.ipv6
        info = ni.ifaddresses(self.name)[ni.AF_INET6]
        self.ipv6["count"] = len(info)
        for address in [ address_type ] if address_type is not None else [ "addr", "netmask", "broadcast", "peer" ]:
            self.ipv6[address] = [ info[i][address] if address in info[i] else None for i in range(self.ipv6["count"]) ]
        return self.ipv6[address_type] if address_type is not None else self.ipv6
    
    def get_mac(self, address_type = None) -> list | dict:
        if ni.AF_LINK not in ni.ifaddresses(self.name):
            self.mac["count"] = 0
            return self.mac[address_type] if address_type is not None else self.mac
        info = ni.ifaddresses(self.name)[ni.AF_LINK]
        self.mac["count"] = len(info)
        for address in [ address_type ] if address_type is not None else [ "addr", "peer" ]:
            self.mac[address] = [ info[i][address] if address in info[i] else None for i in range(self.mac["count"]) ]
        return self.mac[address_type] if address_type is not None else self.mac
    
    def send(self, packet, capture_response = False, timeout = 5):
        return srp(packet, iface=self.name, threaded = False, timeout = timeout, verbose = False)
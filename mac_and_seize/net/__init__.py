"""Shared network domain layer.

The tool's ubiquitous domain vocabulary - interfaces, packets, addresses, routes
- and the OS/scapy adapters that operate on them. It sits *below* the feature
modules so that every module speaks the same nouns without importing one another
(modules are independent plugins). See ``README.md`` for the model/adapters split
and the dependency rule.

Model types are re-exported here for a flat import
(``from mac_and_seize.net import Interface, Packet, MacAddress``); adapters are
imported as modules so calls stay self-documenting
(``from mac_and_seize.net.adapters import ip`` -> ``ip.set_link_state(...)``).
"""

from __future__ import annotations

from mac_and_seize.net.model.addresses import CIDR, IPAddress, MacAddress
from mac_and_seize.net.model.interface import Interface
from mac_and_seize.net.model.packet import Packet
from mac_and_seize.net.model.route import Route

__all__ = [
    "CIDR",
    "IPAddress",
    "Interface",
    "MacAddress",
    "Packet",
    "Route",
]

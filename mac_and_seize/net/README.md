# `net/` — shared network domain layer

This package holds the tool's **domain vocabulary** — interfaces, packets,
addresses, routes — and the **infrastructure adapters** that operate on them. It
exists so that feature modules under `modules/` can speak the same nouns without
importing each other (modules are independent, auto-discovered plugins — see
[`../modules/README.md`](../modules/README.md)).

## Why it exists

A module must never import another module. So any type that more than one feature
needs — an `Interface`, a `Packet`, a validated `MacAddress` — cannot live inside
a feature module; it has to sit in a shared layer *below* the modules. That is
this package. Feature services became thin orchestrators that compose these
pieces instead of defining them.

## Layout

```
net/
  model/        pure domain types — NO I/O, NO subprocess/scapy calls
    addresses.py   MacAddress, IPAddress, CIDR   (self-validating value objects)
    route.py       Route                          (value object + is_autorecreated)
    interface.py   Interface                       (entity: data + to_dict)
    packet.py      Packet                          (scapy wrapper + factories + inspection)
  adapters/     infrastructure — the only place OS/scapy calls live
    privileged.py  run(), PrivilegedCommandError, family_flag()
    ip.py          link/addr/route ops via `ip`, + sysfs read_state/is_up
    ethtool.py     get_permanent_mac() via SIOCETHTOOL ioctl
    netifaces_io.py list_names(), read_addresses()
    scapy_io.py    send(), sniff(), write/read_pcap(), available_interfaces(), expand_hosts(), arp/icmp_probe()
```

## Dependency rule

```
modules/  →  net/  →  core/
```

- `net/` may import `core` (e.g. `core.errors.ModuleError`) and third-party libs.
- `net/` must **never** import `cli`, `server`, or any `modules.*`.
- Within `net/`: `adapters/` may import `model/`; `model/` must **not** import
  `adapters/` (the model stays pure). This is why turning a `Route` into an
  `ip route replace` command line lives in `adapters/ip.py`, not on `Route`.
- `net/` is **not** under `modules/`, so plugin discovery
  ([`../core/plugins.py`](../core/plugins.py)) never tries to register it.

## Using it from a module

```python
from mac_and_seize.net import Interface, Packet, MacAddress, CIDR   # model: flat
from mac_and_seize.net.adapters import ip, scapy_io                 # adapters: as modules

mac = MacAddress.parse(raw)          # validate at the boundary
ip.set_mac_address("eth0", mac)      # adapter serialises the value object to `ip`
```

Value objects validate on `parse(...)` and raise `ValueError` on bad input;
adapters accept the value objects and serialise them to `ip`/scapy at the edge,
so anything reaching the OS is already well-formed.

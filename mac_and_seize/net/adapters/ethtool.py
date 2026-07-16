"""Read an interface's permanent (factory) MAC via a raw ``SIOCETHTOOL`` ioctl.

This is the same call ``ethtool -P`` makes, done directly so no external
``ethtool`` binary is required. Linux-specific.
"""

from __future__ import annotations

import array
import fcntl
import socket
import struct

from mac_and_seize.net.model.addresses import MacAddress

# ioctl / ethtool constants (from <linux/sockios.h> and <linux/ethtool.h>).
_SIOCETHTOOL = 0x8946
_ETHTOOL_GPERMADDR = 0x00000020
_MAX_ADDR_LEN = 32
_IFNAMSIZ = 16


def get_permanent_mac(name: str) -> MacAddress | None:
    """Return the interface's permanent (factory) MAC via ``SIOCETHTOOL``.

    Uses the ``ETHTOOL_GPERMADDR`` ioctl (no external ``ethtool`` dependency).
    Returns ``None`` when the address cannot be determined - e.g. the driver
    does not support it (virtual interfaces) or it reports all-zeros.
    """
    if len(name.encode()) >= _IFNAMSIZ:
        raise ValueError(f"Interface name too long: {name!r}")

    # struct ethtool_perm_addr { __u32 cmd; __u32 size; __u8 data[]; }
    ecmd = array.array(
        "B",
        struct.pack("II", _ETHTOOL_GPERMADDR, _MAX_ADDR_LEN) + b"\x00" * _MAX_ADDR_LEN,
    )
    buf_addr, _ = ecmd.buffer_info()
    # struct ifreq { char ifr_name[IFNAMSIZ]; ... void *ifr_data; }
    ifreq = struct.pack(f"{_IFNAMSIZ}sP", name.encode(), buf_addr)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            fcntl.ioctl(sock.fileno(), _SIOCETHTOOL, ifreq)
        except OSError:
            # EOPNOTSUPP / ENODEV / permission, etc. - caller treats as unknown.
            return None

    size = struct.unpack("II", ecmd[:8].tobytes())[1]
    if size == 0:
        return None
    data = ecmd[8 : 8 + size].tobytes()
    mac = ":".join(f"{byte:02x}" for byte in data)
    if mac == "00:00:00:00:00:00":
        return None
    return MacAddress.parse(mac)

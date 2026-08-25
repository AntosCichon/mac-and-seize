"""Records for one interface's starved address pool, and how it renders.

A :class:`Pool` is everything we know about one attacked segment: the leases we
hold on the legitimate server, the addresses we could not get, and the
subnet-wide settings that server hands out. It is plain data - the service owns
the lock and the worker thread; nothing here starts anything or touches a
socket.

Every address is in exactly one of three states, which is what
``lan dhcp starve list`` colours:

* :data:`FREE`   - we hold the lease and nothing is using the address;
* :data:`LEASED` - we hold the lease *and* the rogue server handed it to a
  client, so two leases now ride on it: ours from the real server (which we
  keep renewing) and the client's from us;
* :data:`TAKEN`  - we could not obtain it. Either it sits outside the server's
  configured range or a real host already holds it; DHCP gives us no way to
  tell those apart, which is why the column reads "taken" rather than guessing.

The state is carried in a text column *and* as a row style, so the table still
reads correctly piped to a file or on a terminal without colour (see
``core/presenter.py``).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from mac_and_seize.core.presenter import ROW_STYLE_KEY
from mac_and_seize.modules.lan.dhcp import protocol
from mac_and_seize.util.format import format_hms

#: We hold the lease; the address is idle and available to the rogue server.
FREE = "free"
#: We hold the lease and have handed the address to a client.
LEASED = "leased"
#: We could not obtain it - outside the server's range, or already in use.
TAKEN = "taken"

#: Row style per state (see :data:`~mac_and_seize.core.presenter.ROW_STYLES`).
#: Held-but-idle addresses are dimmed because they are the quiet background of
#: a successful starve; the eye should land on what is contested (red) or
#: actively in play (green).
_STATE_STYLES = {FREE: "dim", LEASED: "green", TAKEN: "red"}

#: Fallback when a server grants a lease without option 51 (rare, but legal).
_DEFAULT_LEASE_S = 3600.0

#: RFC 2131 §4.4.5 renewal fractions, used when the server omits options 58/59.
_T1_FRACTION = 0.5
_T2_FRACTION = 0.875

#: Largest subnet ``starve list`` will enumerate address-by-address. A /24 is
#: 254 rows and a /20 is 4094 - already far past what anyone reads - while a /16
#: would be 65534, enough to make the view useless and the render slow. Above
#: this the listing degrades gracefully to just the addresses we know about
#: (see :func:`rows`), which is the interesting part of a large subnet anyway.
MAX_SUBNET_ADDRESSES = 4096


@dataclass
class Lease:
    """One address we hold on the legitimate server under a forged MAC.

    ``client_mac`` is the address we invented to obtain it; every renewal must
    reuse it, because that is the identity the server's binding is filed under.
    ``holder_mac`` is set once our rogue server hands the address to a real
    client - a *different* lease with its own, shorter clock (``holder_until``)
    that we must never let outlive our own.

    All deadlines are :func:`time.monotonic` values: a lease must not shift
    because the wall clock did.
    """

    ip: str
    client_mac: str
    server_id: str
    server_mac: str
    granted_at: float
    lease_time: float
    renew_at: float
    rebind_at: float
    expires_at: float
    holder_mac: str | None = None
    holder_until: float | None = None

    @property
    def state(self) -> str:
        return LEASED if self.holder_mac else FREE

    def remaining(self, now: float) -> float:
        return max(0.0, self.expires_at - now)

    @staticmethod
    def _timers(message: protocol.Message) -> tuple[float, float, float]:
        """Read (lease, T1, T2) from a reply, filling in the RFC defaults.

        A server may omit options 58/59, and a badly-configured one can send
        timers at or beyond the lease itself - which would leave us renewing
        only after the binding had already lapsed. Both are clamped back inside
        the lease so the renewal always happens while we still hold it.
        """
        lease = float(protocol.option_int(message.options, "lease_time") or 0)
        if lease <= 0:
            lease = _DEFAULT_LEASE_S
        t1 = float(protocol.option_int(message.options, "renewal_time") or 0)
        t2 = float(protocol.option_int(message.options, "rebinding_time") or 0)
        if not 0 < t1 < lease:
            t1 = lease * _T1_FRACTION
        if not t1 < t2 < lease:
            t2 = lease * _T2_FRACTION
        return lease, t1, t2

    @classmethod
    def from_reply(
        cls, message: protocol.Message, client_mac: str, now: float
    ) -> "Lease":
        """Build a lease from the DHCPACK that granted it."""
        lease, t1, t2 = cls._timers(message)
        return cls(
            ip=message.your_ip,
            client_mac=client_mac,
            server_id=message.server_id or message.src_ip,
            server_mac=message.src_mac,
            granted_at=now,
            lease_time=lease,
            renew_at=now + t1,
            rebind_at=now + t2,
            expires_at=now + lease,
        )

    def renewed(self, message: protocol.Message, now: float) -> None:
        """Reset the timers in place from a renewal's DHCPACK.

        The holder fields are deliberately untouched: renewing our lease with
        the real server says nothing about the client using the address.
        """
        lease, t1, t2 = self._timers(message)
        self.granted_at = now
        self.lease_time = lease
        self.renew_at = now + t1
        self.rebind_at = now + t2
        self.expires_at = now + lease


@dataclass
class Unavailable:
    """An address we tried for and did not get.

    ``last_try`` is ``None`` until we have asked for this address *by name*
    (option 50). Addresses that only ever failed implicitly - they were never
    offered while we drained the pool - have nothing meaningful to report yet.
    """

    ip: str
    last_try: float | None = None
    attempts: int = 0


@dataclass
class SubnetInfo:
    """The subnet-wide settings the legitimate server hands out.

    Learned from the first offer/ack we get and refreshed on later ones, so a
    starve that outlives a server-side config change follows it. Also what the
    ``default`` keyword resolves to when starting the rogue server.
    """

    network: str | None = None
    gateway: str | None = None
    dns: list[str] = field(default_factory=list)
    domain: str | None = None
    ntp: list[str] = field(default_factory=list)
    subnet_mask: str | None = None
    server_id: str | None = None
    server_mac: str | None = None
    lease_time: int | None = None

    def update(self, message: protocol.Message) -> None:
        """Absorb whatever this reply tells us; keep what it doesn't mention."""
        options = message.options
        mask = options.get("subnet_mask")
        if mask and message.your_ip and message.your_ip != protocol.UNSPECIFIED_IP:
            self.subnet_mask = str(mask)
            try:
                self.network = str(
                    ipaddress.ip_interface(f"{message.your_ip}/{mask}").network
                )
            except ValueError:  # a server sending a nonsense mask
                self.network = None
        routers = protocol.option_ips(options, "router")
        if routers:
            self.gateway = routers[0]
        dns = protocol.option_ips(options, "name_server")
        if dns:
            self.dns = dns
        domain = protocol.option_text(options, "domain")
        if domain:
            self.domain = domain
        ntp = protocol.option_ips(options, "NTP_server")
        if ntp:
            self.ntp = ntp
        if message.server_id:
            self.server_id = message.server_id
        if message.src_mac:
            self.server_mac = message.src_mac
        lease = protocol.option_int(options, "lease_time")
        if lease:
            self.lease_time = lease

    def as_row(self) -> dict:
        """Render the subnet-wide facts as a key/value block."""
        return {
            "network": self.network or "-",
            "gateway": self.gateway or "-",
            "dns": ", ".join(self.dns) or "-",
            "domain": self.domain or "-",
            "ntp": ", ".join(self.ntp) or "-",
            "server": self.server_id or "-",
            "server mac": self.server_mac or "-",
            "lease time": format_hms(self.lease_time) if self.lease_time else "-",
        }


@dataclass
class Pool:
    """Everything known about one attacked segment."""

    iface: str
    leases: dict[str, Lease] = field(default_factory=dict)
    unavailable: dict[str, Unavailable] = field(default_factory=dict)
    subnet: SubnetInfo = field(default_factory=SubnetInfo)
    #: Set once the server stops offering new addresses. Acquisition then stops
    #: but the retry pass keeps probing the addresses we never got.
    exhausted: bool = False

    def free_leases(self) -> list[Lease]:
        return [lease for lease in self.leases.values() if lease.holder_mac is None]

    def held_leases(self) -> list[Lease]:
        return [lease for lease in self.leases.values() if lease.holder_mac is not None]

    def seed_unavailable(self) -> None:
        """Mark every address in the subnet we don't hold as unobtained.

        Called when acquisition runs dry: at that moment everything still
        missing is, by definition, something the server would not give us.
        Skipped for a subnet too large to enumerate (see
        :data:`MAX_SUBNET_ADDRESSES`) - there the pool only ever tracks
        addresses it has actually seen.
        """
        for ip in _subnet_addresses(self.subnet.network):
            if ip not in self.leases:
                self.unavailable.setdefault(ip, Unavailable(ip=ip))

    def reap_expired(self, now: float) -> list[str]:
        """Drop leases whose time ran out; return the addresses lost.

        Called lazily whenever the pool is read, so a stopped starve still ages
        its pool correctly without a thread running to do it (see
        ``modules/README.md`` §9 on finalizing self-stopped work lazily).
        """
        lost = [ip for ip, lease in self.leases.items() if lease.expires_at <= now]
        for ip in lost:
            del self.leases[ip]
            self.unavailable[ip] = Unavailable(ip=ip, last_try=now)
        return lost


def _ip_key(ip: str):
    """Sort addresses numerically (``.5`` before ``.10``), unparseable last."""
    try:
        return (0, int(ipaddress.IPv4Address(ip)))
    except ValueError:
        return (1, 0)


def _subnet_addresses(network: str | None) -> list[str]:
    """Every assignable address in ``network``, or ``[]`` if it's too big/unknown."""
    if not network:
        return []
    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return []
    if parsed.num_addresses > MAX_SUBNET_ADDRESSES:
        return []
    return [str(ip) for ip in parsed.hosts()]


def rows(pool: Pool, now: float) -> list[dict]:
    """Render the pool as one row per address, ordered numerically.

    Covers every address in the subnet plus anything we know about outside it,
    so the listing is the whole segment rather than only our successes. For a
    subnet past :data:`MAX_SUBNET_ADDRESSES` only known addresses are listed.

    ``lease left`` counts down *our* lease with the real server (the one that
    matters - when it lapses we lose the address); ``holder`` and ``holder
    left`` describe the client our rogue server gave it to.
    """
    known = set(pool.leases) | set(pool.unavailable)
    addresses = sorted(
        known.union(_subnet_addresses(pool.subnet.network)), key=_ip_key
    )
    rendered: list[dict] = []
    for ip in addresses:
        lease = pool.leases.get(ip)
        if lease is not None:
            holder_left = "-"
            if lease.holder_until is not None:
                holder_left = format_hms(max(0.0, lease.holder_until - now))
            rendered.append(
                {
                    "ip": ip,
                    "state": lease.state,
                    "lease left": format_hms(lease.remaining(now)),
                    "holder": lease.holder_mac or "-",
                    "holder left": holder_left,
                    "last try": "-",
                    ROW_STYLE_KEY: _STATE_STYLES[lease.state],
                }
            )
            continue
        entry = pool.unavailable.get(ip)
        last_try = "-"
        if entry is not None and entry.last_try is not None:
            last_try = format_hms(max(0.0, now - entry.last_try))
        rendered.append(
            {
                "ip": ip,
                "state": TAKEN,
                "lease left": "-",
                "holder": "-",
                "holder left": "-",
                "last try": last_try,
                ROW_STYLE_KEY: _STATE_STYLES[TAKEN],
            }
        )
    return rendered

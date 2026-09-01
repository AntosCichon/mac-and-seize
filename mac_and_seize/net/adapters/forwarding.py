"""Kernel forwarding and firewall state for the relay module.

Two surfaces live here, both reached through the shared privileged-subprocess
helper (:mod:`~mac_and_seize.net.adapters.privileged`) so a missing ``sysctl``
or ``nft`` binary surfaces as a clean :class:`PrivilegedCommandError`:

* **Sysctl snapshot/restore** (:class:`SysctlSnapshot` + :func:`snapshot_and_set`
  / :func:`restore_sysctls`). Reads a ``net.*`` key, records the original
  value, and writes the target. Mirrors the shape of
  :func:`~mac_and_seize.net.adapters.ip.capture_routes` /
  :func:`~mac_and_seize.net.adapters.ip.restore_routes` but for kernel
  toggles rather than routes.
* **nftables named tables** (:data:`INPUT_DROP_TABLE`,
  :data:`MASQUERADE_TABLE`). Two dedicated tables the relay owns end to end,
  so create/delete is idempotent and does not have to reason about the
  operator's own rules:

  - ``inet mas_relay`` (INPUT drop) - dropped in the ``filter`` INPUT hook
    for frames whose L2 destination is us but whose L3 destination is not,
    so the kernel does not double-process what the scapy relay is
    handling.
  - ``ip mas_relay_nat`` (POSTROUTING masquerade) - used only by the
    ``dhcp server --nat-relay`` engine; scoped to a named set of
    ``ip saddr`` values so only the served leases are NATed.

:func:`purge_stale_tables` deletes either table if it was left behind by a
prior unclean exit, so the relay is self-healing across restarts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from mac_and_seize.net.adapters.privileged import PrivilegedCommandError, run
from mac_and_seize.observability import get_logger

_log = get_logger(__name__)

#: nftables table names the relay owns. Dedicated names keep create/delete
#: idempotent and separate from any rules the operator maintains outside.
INPUT_DROP_TABLE = "mas_relay"
MASQUERADE_TABLE = "mas_relay_nat"

#: Name of the nftables set inside :data:`MASQUERADE_TABLE` holding the source
#: addresses that get masqueraded. Rebuilt from scratch by
#: :func:`install_masquerade`; extended/pruned by
#: :func:`add_masquerade_source` / :func:`remove_masquerade_source` as the
#: rogue DHCP server hands out or reclaims leases.
_MASQUERADED_SET = "masqueraded"


# --- Sysctl snapshot/restore ------------------------------------------------


@dataclass
class SysctlSnapshot:
    """Original values of the sysctl keys a relay has forced.

    The keys are recorded on their *first* write (see :func:`snapshot_and_set`)
    so restore returns each key to the value it had before this relay started,
    not to whatever a later write happened to set it to.
    """

    entries: dict[str, str] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not self.entries


def _read_sysctl(key: str) -> str:
    """Read one sysctl key. Raises :class:`PrivilegedCommandError` on failure."""
    result = run(["sysctl", "-n", key])
    return (result.stdout or "").strip()


def _write_sysctl(key: str, value: str) -> None:
    """Write one sysctl key. Raises :class:`PrivilegedCommandError` on failure."""
    run(["sysctl", "-w", f"{key}={value}"])


def snapshot_and_set(
    snapshot: SysctlSnapshot, key: str, target_value: str
) -> None:
    """Record ``key``'s current value (if not already recorded) and set it.

    A second call for the same key writes the target value but keeps the first
    reading as the "real" one, so :func:`restore_sysctls` returns to whatever
    the operator had before the *first* relay touched it.
    """
    if key not in snapshot.entries:
        snapshot.entries[key] = _read_sysctl(key)
    _write_sysctl(key, target_value)
    _log.info(
        "sysctl %s := %s (was %r)", key, target_value, snapshot.entries[key]
    )


def restore_sysctls(snapshot: SysctlSnapshot) -> None:
    """Write every snapshotted sysctl back to its original value (best-effort).

    Failures on individual keys are logged and the loop continues; teardown
    must never raise at the prompt. The snapshot is emptied even on failure so
    a subsequent relay start records fresh values.
    """
    for key, value in snapshot.entries.items():
        try:
            _write_sysctl(key, value)
            _log.info("sysctl %s restored to %r", key, value)
        except PrivilegedCommandError as exc:
            _log.warning(
                "Could not restore sysctl %s to %r: %s", key, value, exc
            )
    snapshot.entries.clear()


# --- Nftables: table lifecycle ----------------------------------------------


def _table_exists(family: str, name: str) -> bool:
    """Whether an nftables table of ``family``/``name`` currently exists.

    A missing ``nft`` binary or any listing failure is treated as "no", so
    callers can pre-check before mutating without a special-case for hosts
    without nftables installed.
    """
    try:
        result = run(["nft", "list", "tables"])
    except PrivilegedCommandError:
        return False
    target = f"table {family} {name}"
    return any(line.strip() == target for line in (result.stdout or "").splitlines())


def _delete_table(family: str, name: str) -> None:
    """Delete an nftables table if it exists; silent when it does not."""
    if not _table_exists(family, name):
        return
    try:
        run(["nft", "delete", "table", family, name])
    except PrivilegedCommandError as exc:
        _log.warning(
            "Could not delete nftables table %s %s: %s", family, name, exc
        )


def purge_stale_tables() -> list[str]:
    """Delete relay-owned nftables tables left over from a prior process.

    Called from :class:`~mac_and_seize.modules.relay.service.RelayService`'s
    constructor so a SIGKILL or power-loss in a previous run does not leave
    inert firewall state cluttering the system across a restart. Returns the
    list of tables actually deleted (for logging).
    """
    deleted: list[str] = []
    for family, name in (("inet", INPUT_DROP_TABLE), ("ip", MASQUERADE_TABLE)):
        if _table_exists(family, name):
            _delete_table(family, name)
            deleted.append(f"{family} {name}")
    return deleted


# --- Nftables: INPUT drop (mas_relay) ---------------------------------------


def install_input_drop(entries: Iterable[tuple[str, str, str]]) -> None:
    """(Re)build :data:`INPUT_DROP_TABLE` from scratch with one rule per entry.

    ``entries`` is an iterable of ``(iface, our_ether_mac, our_ip)``. Each
    entry becomes a rule that drops frames arriving on ``iface`` whose L2
    destination is ``our_ether_mac`` but whose L3 destination is not
    ``our_ip``. The kernel therefore never processes what the scapy relay is
    handling and cannot reply with ICMP-unreachable, RST, or a stray forward.

    Rebuilt-from-scratch semantics keep this idempotent: the caller may pass
    the full current set every time a flow starts or stops, and this function
    replaces the table's contents in one shot.
    """
    listed = list(entries)
    _delete_table("inet", INPUT_DROP_TABLE)
    if not listed:
        return
    run(["nft", "add", "table", "inet", INPUT_DROP_TABLE])
    run([
        "nft", "add", "chain", "inet", INPUT_DROP_TABLE, "input",
        "{ type filter hook input priority -100 ; policy accept ; }",
    ])
    for iface, ether_mac, ip_self in listed:
        run([
            "nft", "add", "rule", "inet", INPUT_DROP_TABLE, "input",
            "iifname", iface,
            "ether", "daddr", ether_mac,
            "ip", "daddr", "!=", ip_self,
            "drop",
        ])
    _log.info(
        "Installed nftables INPUT drop with %d rule(s): %s",
        len(listed),
        ", ".join(f"{i}/{m}/!={ip}" for i, m, ip in listed),
    )


def remove_input_drop() -> None:
    """Delete :data:`INPUT_DROP_TABLE` entirely."""
    _delete_table("inet", INPUT_DROP_TABLE)
    _log.info("Removed nftables INPUT drop table %r", INPUT_DROP_TABLE)


# --- Nftables: MASQUERADE (mas_relay_nat) -----------------------------------


def install_masquerade(uplink_iface: str, source_addrs: Iterable[str]) -> None:
    """Create :data:`MASQUERADE_TABLE` masquerading the given source addresses.

    A named set (:data:`_MASQUERADED_SET`) holds the addresses actually
    masqueraded; the POSTROUTING rule matches ``ip saddr @masqueraded`` so
    only the served leases are NATed, leaving the operator's own traffic on
    the same iface untouched.

    Extend or prune the set later with :func:`add_masquerade_source` /
    :func:`remove_masquerade_source`.
    """
    _delete_table("ip", MASQUERADE_TABLE)
    listed = list(source_addrs)
    run(["nft", "add", "table", "ip", MASQUERADE_TABLE])
    run([
        "nft", "add", "set", "ip", MASQUERADE_TABLE, _MASQUERADED_SET,
        "{ type ipv4_addr ; }",
    ])
    run([
        "nft", "add", "chain", "ip", MASQUERADE_TABLE, "postrouting",
        "{ type nat hook postrouting priority 100 ; policy accept ; }",
    ])
    run([
        "nft", "add", "rule", "ip", MASQUERADE_TABLE, "postrouting",
        "oifname", uplink_iface,
        "ip", "saddr", f"@{_MASQUERADED_SET}",
        "masquerade",
    ])
    for addr in listed:
        add_masquerade_source(addr)
    _log.info(
        "Installed nftables NAT MASQUERADE on egress %s for %d source(s)",
        uplink_iface, len(listed),
    )


def add_masquerade_source(addr: str) -> None:
    """Add one address to the masqueraded set (best-effort, idempotent-ish)."""
    try:
        run([
            "nft", "add", "element", "ip", MASQUERADE_TABLE,
            _MASQUERADED_SET, f"{{ {addr} }}",
        ])
    except PrivilegedCommandError as exc:
        _log.debug("Could not add %s to masqueraded set: %s", addr, exc)


def remove_masquerade_source(addr: str) -> None:
    """Remove one address from the masqueraded set (best-effort)."""
    try:
        run([
            "nft", "delete", "element", "ip", MASQUERADE_TABLE,
            _MASQUERADED_SET, f"{{ {addr} }}",
        ])
    except PrivilegedCommandError as exc:
        _log.debug("Could not remove %s from masqueraded set: %s", addr, exc)


def remove_masquerade() -> None:
    """Delete :data:`MASQUERADE_TABLE` entirely."""
    _delete_table("ip", MASQUERADE_TABLE)
    _log.info("Removed nftables NAT table %r", MASQUERADE_TABLE)

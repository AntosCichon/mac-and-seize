"""Wireless (802.11) interface control via PyRIC - the pure-Python nl80211 port.

The one place monitor-mode and channel operations touch the OS. PyRIC talks to
the kernel over netlink (nl80211) directly, so no external tool (``iw`` /
``airmon-ng``) is spawned. PyRIC's ``Card`` handle is kept **behind this seam**:
callers pass interface *names* and never see netlink details, mirroring how
``ip.py``/``ethtool.py`` hide their transports. If PyRIC ever proves unreliable
on a given driver, only this file changes (swap to an ``iw`` subprocess).

Linux-specific, matching the rest of the app. State changes (mode/channel)
require root; the CLI gates those actions with ``requires_root``.
"""

from __future__ import annotations

import os
import warnings

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.observability import get_logger
from mac_and_seize.util.parse import split_values

# PyRIC 0.1.6.3 emits a benign SyntaxWarning (an unescaped ``\d`` in a regex) at
# import/compile time. Silence it at this boundary, the same way scapy_io quiets
# scapy's runtime logger - it is noise, not a problem we can fix upstream.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", SyntaxWarning)
    import pyric
    import pyric.pyw as pyw

_log = get_logger(__name__)

# IEEE 802.11 channel numbers we recognise: 2.4 GHz (b/g/n) and the 5 GHz UNII
# bands (a/n/ac). 6 GHz (Wi-Fi 6E) is deliberately out of scope for now. This is
# the reference set used to reject channels the standard does not define before
# ever asking a card to tune to one.
_CHANNELS_2GHZ = tuple(range(1, 15))  # 1..14 (14 is 802.11b / Japan only)
_CHANNELS_5GHZ = (
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
)
IEEE_CHANNELS: tuple[int, ...] = _CHANNELS_2GHZ + _CHANNELS_5GHZ


class WirelessError(ModuleError):
    """A wireless/nl80211 operation failed (device missing, driver refused, ...)."""


# --- Channel vocabulary ----------------------------------------------------


def ieee_channels() -> list[int]:
    """Every IEEE 802.11 channel number this tool recognises (2.4 + 5 GHz)."""
    return list(IEEE_CHANNELS)


def band_2ghz_channels() -> list[int]:
    """The 2.4 GHz IEEE channels this tool recognises (1-14), in order.

    The band that is (almost) always legal to *transmit* on in monitor mode - 5
    GHz channels are frequently flagged NO-IR by the regulatory domain, so a
    beacon injected there never actually leaves the radio. Used as the default
    band for beacon injection.
    """
    return list(_CHANNELS_2GHZ)


def parse_channel_spec(spec: str) -> list[int]:
    """Parse a channel spec - a number, comma list, range, or ``all`` - to numbers.

    The shared ``--sweep`` / ``--channel`` grammar: ``all`` expands to every IEEE
    802.11 channel this tool recognises; otherwise commas and inclusive ranges
    (via :func:`~mac_and_seize.util.parse.split_values`, e.g. ``1,6,11`` or
    ``1-11``) are expanded. Raises :class:`ValueError` on a non-numeric token or
    an empty spec. Does **not** check the card can tune the result - intersect
    with :func:`supported_channels` for that.
    """
    spec = spec.strip().lower()
    if spec == "all":
        return ieee_channels()
    channels: list[int] = []
    for value in split_values(spec):
        if not value.isdigit():
            raise ValueError(
                f"Invalid channel {value!r}; expected a number, list, range, or 'all'."
            )
        channels.append(int(value))
    if not channels:
        raise ValueError("No channels given.")
    return channels


def supported_channels(name: str) -> list[int]:
    """The IEEE channels this card can actually tune, in IEEE order.

    Read from the driver via nl80211 so a sweep can skip channels the radio
    cannot honour - most importantly the 5 GHz band on a 2.4 GHz-only adapter -
    instead of wasting the hop cycle failing to set them (which also parks the
    card on the last good channel and starves the others). Falls back to every
    IEEE channel if the driver does not report its channel set.
    """
    card = _card(name)
    try:
        channels = pyw.devchs(card)
    except pyric.error as exc:
        _log.debug("Could not read supported channels of %s: %s", name, exc)
        return list(IEEE_CHANNELS)
    allowed = set(IEEE_CHANNELS) & {int(c) for c in channels}
    return [c for c in IEEE_CHANNELS if c in allowed] or list(IEEE_CHANNELS)


def validate_channels(channels: list[int]) -> tuple[list[int], list[int]]:
    """Split ``channels`` into ``(valid, rejected)`` against :data:`IEEE_CHANNELS`.

    Order is preserved and duplicates dropped. ``rejected`` collects numbers that
    are not IEEE 802.11 channels so callers can report them (used by the capture
    ``--sweep`` option). This is the "logical AND with the possible Wi-Fi
    channels" step done in pure data, before any card is touched.
    """
    valid: list[int] = []
    rejected: list[int] = []
    seen: set[int] = set()
    allowed = set(IEEE_CHANNELS)
    for channel in channels:
        if channel in seen:
            continue
        seen.add(channel)
        (valid if channel in allowed else rejected).append(channel)
    return valid, rejected


# --- Interface queries (no privileges required) ----------------------------


def is_wireless(name: str) -> bool:
    """Whether ``name`` is an 802.11 (cfg80211) interface.

    Uses the sysfs ``phy80211`` symlink - the definitive nl80211 marker - so it
    needs no privileges and no netlink round-trip. A vanished interface reads as
    not wireless.
    """
    return os.path.exists(f"/sys/class/net/{name}/phy80211")


def _card(name: str):
    """Resolve an interface name to a PyRIC ``Card``, or raise :class:`WirelessError`."""
    if not is_wireless(name):
        raise WirelessError(f"{name!r} is not a wireless interface.")
    try:
        return pyw.getcard(name)
    except pyric.error as exc:
        raise WirelessError(f"Could not open wireless device {name!r}: {exc}") from exc


def phy_siblings(name: str) -> list[tuple[str, str]]:
    """Other interfaces sharing this card's radio (PHY), as ``(dev, mode)``.

    A monitor interface cannot change channel while another interface on the
    same radio is in use: nl80211 pins the whole PHY to the channel that
    interface is associated on, so ``set_channel`` fails with "device busy" for
    every other channel. Listing the siblings lets callers explain a stuck
    sweep. Excludes the interface itself; returns ``[]`` on any error.
    """
    try:
        card = _card(name)
        return [
            (sibling.dev, mode)
            for sibling, mode in pyw.ifaces(card)
            if sibling.dev != name
        ]
    except (pyric.error, WirelessError, OSError) as exc:
        _log.debug("Could not list PHY siblings of %s: %s", name, exc)
        return []


#: Connection managers that, when running, keep a Wi-Fi card on its associated
#: channel - the usual reason a monitor-mode sweep can't hop. ``airmon-ng check
#: kill`` stops these (modern airmon-ng handles iwd too).
_RADIO_HOLDERS = ("iwd", "NetworkManager", "wpa_supplicant")


def interfering_daemons() -> list[str]:
    """Names of running connection managers likely to be holding the Wi-Fi radio.

    Complements :func:`phy_siblings`: that only spots *another interface* on the
    same PHY, but the common case is a single interface (``wlan0``) whose radio
    is held by a daemon with no sibling VIF to point at. Reads process names
    from ``/proc``; best-effort, returns ``[]`` if it cannot be read.
    """
    found: list[str] = []
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                with open(f"/proc/{entry.name}/comm", encoding="ascii") as fh:
                    comm = fh.read().strip()
            except OSError:
                continue
            if comm in _RADIO_HOLDERS and comm not in found:
                found.append(comm)
    except OSError:
        return []
    return found


# --- PHY (radio) topology --------------------------------------------------


def list_phys() -> list[str]:
    """Every 802.11 PHY (radio) present, by name (e.g. ``['phy0']``).

    Reads sysfs, so it needs no privileges and, crucially, still lists a radio
    whose netdev has been removed - the case after iwd (which owns interface
    lifecycle by default) is stopped and ``wlan0`` disappears while ``phy0``
    survives. That surviving PHY is what a monitor interface is created on.
    """
    try:
        return sorted(os.listdir("/sys/class/ieee80211"))
    except OSError:
        return []


def sole_phy() -> str | None:
    """The only PHY present, or ``None`` if there are zero or several."""
    phys = list_phys()
    return phys[0] if len(phys) == 1 else None


def phy_of(name: str) -> str | None:
    """The PHY backing interface ``name`` (e.g. ``'phy0'``), or ``None``."""
    try:
        target = os.path.realpath(f"/sys/class/net/{name}/phy80211")
    except OSError:
        return None
    base = os.path.basename(target)
    return base if base.startswith("phy") else None


def interfaces_on_phy(phy: str) -> list[tuple[str, str]]:
    """``(dev, mode)`` for every netdev currently on ``phy``."""
    result: list[tuple[str, str]] = []
    try:
        devs = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return result
    for dev in devs:
        if phy_of(dev) != phy:
            continue
        try:
            result.append((dev, current_mode(dev)))
        except WirelessError:
            result.append((dev, "?"))
    return result


def _phy_index(phy: str) -> int:
    try:
        with open(f"/sys/class/ieee80211/{phy}/index", encoding="ascii") as fh:
            return int(fh.read().strip())
    except OSError as exc:
        raise WirelessError(f"No such wireless PHY {phy!r}.") from exc


def current_mode(name: str) -> str:
    """Return the interface's 802.11 mode (e.g. ``'monitor'``, ``'managed'``)."""
    card = _card(name)
    try:
        return pyw.devinfo(card)["mode"]
    except pyric.error as exc:
        raise WirelessError(f"Could not read the mode of {name!r}: {exc}") from exc


def current_channel(name: str) -> int | None:
    """Return the channel the interface is tuned to, or ``None`` if unset."""
    card = _card(name)
    try:
        return pyw.chget(card)
    except pyric.error as exc:
        raise WirelessError(f"Could not read the channel of {name!r}: {exc}") from exc


# --- State changes (require root) ------------------------------------------


def set_mode(name: str, mode: str) -> None:
    """Switch the interface to ``mode`` (e.g. ``'monitor'`` / ``'managed'``).

    nl80211 requires the link to be down to change its type, so the interface is
    brought down, retyped, and brought back up. Raises :class:`WirelessError` if
    the driver does not support the mode or refuses the change (commonly because
    a network manager is holding the interface). Requires root.
    """
    card = _card(name)
    try:
        supported = pyw.devmodes(card)
    except pyric.error as exc:
        raise WirelessError(f"Could not query the modes of {name!r}: {exc}") from exc
    if mode not in supported:
        raise WirelessError(
            f"{name!r} does not support {mode!r} mode "
            f"(supported: {', '.join(supported) or 'none reported'})."
        )
    try:
        pyw.down(card)
        pyw.modeset(card, mode)
        pyw.up(card)
    except pyric.error as exc:
        raise WirelessError(
            f"Could not set {name!r} to {mode!r} mode: {exc}. A network manager "
            "(NetworkManager/wpa_supplicant) may be holding the interface - stop "
            "or unmanage it and try again."
        ) from exc
    _log.info("Set %s to %s mode", name, mode)


def set_channel(name: str, channel: int) -> None:
    """Tune a monitor-mode interface to ``channel`` (requires root).

    Validates that ``channel`` is an IEEE 802.11 channel and that the interface
    is in monitor mode first (tuning is only meaningful there), then asks the
    card to switch. A channel the card cannot honour surfaces as a
    :class:`WirelessError`.
    """
    if channel not in IEEE_CHANNELS:
        raise ValueError(
            f"{channel} is not an IEEE 802.11 defined Wi-Fi channel."
        )
    card = _card(name)
    try:
        mode = pyw.devinfo(card)["mode"]
    except pyric.error as exc:
        raise WirelessError(f"Could not read the mode of {name!r}: {exc}") from exc
    if mode != "monitor":
        raise WirelessError(
            f"{name!r} is in {mode!r} mode; the channel can only be set in "
            "monitor mode."
        )
    try:
        if not pyw.isup(card):
            pyw.up(card)
        pyw.chset(card, channel, None)
    except pyric.error as exc:
        raise WirelessError(
            f"Could not set {name!r} to channel {channel}: {exc} "
            "(the card may not support this channel)."
        ) from exc
    # Verify the radio actually retuned. Some drivers accept the channel set in
    # standalone monitor mode without moving the RF hardware - notably Realtek
    # rtw88 (rtw88_8821ce/8822be/...), which stays parked on the last channel the
    # firmware was really tuned to (usually the last associated channel). A sweep
    # then silently only ever sees that one channel. Read it back and fail loud
    # instead. If it can't be read we trust the set rather than false-fail.
    try:
        actual = pyw.chget(card)
    except pyric.error:
        actual = None
    if actual is not None and actual != channel:
        raise WirelessError(
            f"{name!r} stayed on channel {actual} after being told to switch to "
            f"{channel}. The driver likely cannot retune in monitor mode (common "
            "on Realtek rtw88 radios), or a connection manager is holding the "
            "radio - free it with 'sudo airmon-ng check kill' (and 'sudo "
            "systemctl stop iwd' if iwd is running)."
        )
    # Debug, not info: a channel sweep calls this several times a second, and at
    # info it would flood the interactive prompt (see modules/README.md 9).
    _log.debug("Set %s to channel %d", name, channel)


def add_monitor(phy: str, name: str = "mon0") -> str:
    """Create monitor-mode VIF ``name`` on ``phy``, bring it up; return ``name``.

    Targets the PHY by index, so it works even when the PHY has no netdev - the
    reliable path after a connection manager that owns interface lifecycle (iwd)
    has been stopped and its ``wlan0`` is gone. If the PHY is busy because a
    manager still holds it, this fails with a hint; per the tool's instruct-only
    stance it deliberately does **not** stop that daemon itself. Requires root.
    """
    name = name.strip()
    if not name:
        raise ValueError("Specify a name for the monitor interface.")
    if os.path.exists(f"/sys/class/net/{name}"):
        raise WirelessError(f"An interface named {name!r} already exists.")
    index = _phy_index(phy)
    try:
        card = pyw.phyadd(index, name, "monitor")
        pyw.up(card)
    except pyric.error as exc:
        holders = interfering_daemons()
        hint = (
            f" A connection manager ({', '.join(holders)}) is holding this radio; "
            "free it first ('sudo systemctl stop iwd' or 'sudo airmon-ng check "
            "kill') and retry."
        ) if holders else ""
        raise WirelessError(
            f"Could not create monitor interface {name!r} on {phy}: {exc}.{hint}"
        ) from exc
    _log.info("Created monitor interface %s on %s", name, phy)
    return name


def del_interface(name: str) -> None:
    """Delete a (virtual) wireless interface, e.g. one from :func:`add_monitor`."""
    card = _card(name)
    try:
        pyw.devdel(card)
    except pyric.error as exc:
        raise WirelessError(f"Could not delete interface {name!r}: {exc}") from exc
    _log.info("Deleted wireless interface %s", name)

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
            f"monitor mode. Run 'interface mode {name} monitor' first."
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
    # Debug, not info: a channel sweep calls this several times a second, and at
    # info it would flood the interactive prompt (see modules/README.md 9).
    _log.debug("Set %s to channel %d", name, channel)

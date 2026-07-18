"""802.11 (monitor-mode) capture session service.

The wireless counterpart to :class:`~mac_and_seize.modules.capture.service.CaptureService`.
It reuses the shared background-capture lifecycle
(:class:`~mac_and_seize.modules.capture.session.PacketSession`) but captures on a
single monitor-mode interface, filters with the 802.11 vocabulary
(bssid/ssid/type/subtype), and inspects frames as Dot11 rather than Ethernet.

On top of Phase-1 capture it adds:

* **channel sweep** - ``start(..., sweep=...)`` tunes a single channel for the
  whole capture, or hops across a list/range/``all`` every ``interval`` ms via a
  background hopper thread (monitor mode only sees one channel at a time);
* an **activity scan** - :meth:`scan_activity` briefly dwells on each channel and
  ranks them by traffic, so the busiest channels can be chosen for a sweep;
* **network/station views** aggregated from the captured frames.

Registered as a **second** service of the capture module (key
``"capture_wireless"``) so the wired and wireless stores/filters stay separate.
Sniffing and tuning require root; the CLI gates the actions.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.modules.capture.filters import split_values
from mac_and_seize.modules.capture.session import PacketSession
from mac_and_seize.modules.capture.wireless_filters import (
    ACTIONS,
    FIELDS,
    SUBTYPE_NAMES,
    TYPE_NAMES,
    WirelessFilter,
    build_wireless_predicate,
)
from mac_and_seize.net import MacAddress
from mac_and_seize.net.adapters import scapy_io, wireless

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

#: Default milliseconds between channel hops when sweeping several channels.
#: ~250 ms is about two beacon intervals (a beacon is sent every 102.4 ms), so
#: each visit reliably catches a beacon while still cycling quickly - a fast
#: activity sweep rather than steady single-channel monitoring.
DEFAULT_HOP_INTERVAL_MS = 250

#: Default milliseconds to dwell on each channel during an activity scan.
DEFAULT_DWELL_MS = 250


class WirelessCaptureService(PacketSession):
    """Background 802.11 capture with a per-session store of frames and filters."""

    def __init__(self) -> None:
        super().__init__()
        self.filters: list[WirelessFilter] = []
        self._next_id = 1
        self._hopper_stop: threading.Event | None = None
        self._hopper_thread: threading.Thread | None = None

    # --- Background capture ---------------------------------------------------

    def start(
        self,
        context: "AppContext",
        interface: str,
        *,
        time: int | None = None,
        count: int | None = None,
        sweep: str | None = None,
        interval: int | None = None,
    ) -> str:
        """Start a background 802.11 capture on a monitor-mode ``interface``.

        ``sweep`` optionally selects the channel(s): a single channel is tuned
        for the whole capture; a list/range/``all`` hops across them every
        ``interval`` ms (default :data:`DEFAULT_HOP_INTERVAL_MS`).
        """
        interface = self._require_monitor(interface)
        if interval is not None and interval <= 0:
            raise ValueError("--interval must be a positive number of milliseconds.")

        hop_channels: list[int] | None = None
        rejected: list[int] = []
        unsupported: list[int] = []
        if sweep:
            valid, rejected = wireless.validate_channels(self._parse_channels(sweep))
            if not valid:
                raise ValueError("No valid IEEE 802.11 channels to sweep.")
            # Keep only channels the radio can actually tune. A 2.4 GHz-only card
            # asked to sweep 'all' would otherwise spend most of the cycle failing
            # to set 5 GHz channels - parked on one channel, so only that channel's
            # networks are seen.
            supported = set(wireless.supported_channels(interface))
            tunable = [c for c in valid if c in supported]
            unsupported = [c for c in valid if c not in supported]
            if not tunable:
                raise ModuleError(
                    f"{interface} cannot tune any of the requested channel(s) "
                    f"{valid}. It may be a 2.4 GHz-only radio, or these are "
                    "5 GHz/DFS channels the driver does not support."
                )
            if len(tunable) == 1:
                wireless.set_channel(interface, tunable[0])
            else:
                hop_channels = tunable

        with self._lock:
            predicate = build_wireless_predicate(self.filters)
        outcome = self._launch(
            context, ifaces=[interface], predicate=predicate, time=time, count=count
        )

        hop_interval = interval or DEFAULT_HOP_INTERVAL_MS
        # Only spin up the hopper once the sniffer is actually running.
        if hop_channels and outcome[0] == "started":
            self._start_hopper(interface, hop_channels, hop_interval)

        message = self._compose_start_message(
            interface, outcome, time, count, hop_channels, hop_interval,
            rejected, unsupported,
        )
        # When sweeping, a radio shared with a managed/connected interface is
        # pinned to that interface's channel and the hopper silently can't move -
        # warn up front rather than let it look like there's just no traffic.
        if hop_channels:
            siblings = wireless.phy_siblings(interface)
            if siblings:
                others = ", ".join(f"{dev} ({mode})" for dev, mode in siblings)
                message += (
                    f" NOTE: this radio is also used by {others}; if a connection "
                    "manager holds it the sweep cannot change channel - run "
                    "'sudo airmon-ng check kill' to free the radio."
                )
        return message

    def _compose_start_message(
        self, interface, outcome, time, count, hop_channels, hop_interval,
        rejected, unsupported,
    ) -> str:
        kind, n = outcome
        try:
            channel = wireless.current_channel(interface)
        except ModuleError:
            channel = None

        if hop_channels:
            where = (
                f"sweeping channels {','.join(map(str, hop_channels))} "
                f"every {hop_interval}ms"
            )
        else:
            where = f"channel {channel if channel is not None else 'unset'}"
        head = f"Wireless capture on {interface} ({where})"

        reject_note = ""
        if rejected:
            reject_note += (
                f" channels {rejected} are not IEEE 802.11 defined Wi-Fi channels, "
                "they've been excluded from sweep."
            )
        if unsupported:
            reject_note += (
                f" channels {unsupported} are not tunable by {interface} "
                "(likely a different band the radio does not support); skipped."
            )

        if kind == "immediate":
            return f"{head} finished immediately: {n} frame(s) added.{reject_note}"

        limits = []
        if count:
            limits.append(f"{count} frame(s)")
        if time:
            limits.append(f"{time}s")
        suffix = f" (stops after {' or '.join(limits)})" if limits else ""
        message = (
            f"{head} started in the background{suffix}. "
            "Use 'capture wireless stop' to finish."
        )
        if not hop_channels and channel is None:
            message += (
                f" WARNING: no channel is set on {interface}; monitor capture only "
                f"sees one channel at a time - set one with 'interface channel "
                f"{interface} <n>' or pass --sweep."
            )
        return message + reject_note

    # --- Channel sweep (hopper) ----------------------------------------------

    def _start_hopper(self, interface: str, channels: list[int], interval_ms: int) -> None:
        """Spawn a background thread that retunes ``interface`` across ``channels``."""
        stop = threading.Event()

        def run() -> None:
            index = 0
            while not stop.is_set():
                channel = channels[index % len(channels)]
                try:
                    wireless.set_channel(interface, channel)
                except Exception as exc:  # noqa: BLE001 - a bad channel must not kill the sweep
                    # Debug, not warning: a DFS channel can refuse repeatedly and
                    # this runs every hop - it must not flood the prompt.
                    self._log.debug(
                        "Sweep: could not tune %s to channel %d: %s",
                        interface, channel, exc,
                    )
                index += 1
                stop.wait(interval_ms / 1000.0)

        thread = threading.Thread(target=run, name="wl-channel-hopper", daemon=True)
        with self._lock:
            self._hopper_stop = stop
            self._hopper_thread = thread
        thread.start()
        self._log.info(
            "Channel hopper started on %s (%d channels, %dms)",
            interface, len(channels), interval_ms,
        )

    def _stop_extra(self) -> None:
        """Stop the channel hopper (called from the base on capture finalize)."""
        stop, thread = self._hopper_stop, self._hopper_thread
        self._hopper_stop = None
        self._hopper_thread = None
        if stop is not None:
            stop.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    # --- Activity scan --------------------------------------------------------

    def scan_activity(
        self, interface: str, channels_spec: str, dwell_ms: int
    ) -> tuple[list[dict], list[int]]:
        """Dwell briefly on each channel and rank them by traffic volume.

        ``channels_spec`` is a channel number, list, range, or ``all``. Returns
        ``(rows, rejected)``: ``rows`` are one dict per scanned channel
        (frames/beacons/bytes), sorted busiest first; ``rejected`` are requested
        channels that are not IEEE 802.11 channels. Blocks for roughly
        ``len(channels) x dwell``. The interface's original channel is restored
        afterwards.
        """
        interface = self._require_monitor(interface)
        if self.is_capturing():
            raise ModuleError(
                "A wireless capture is running; stop it before scanning activity."
            )
        if dwell_ms <= 0:
            raise ValueError("--dwell must be a positive number of milliseconds.")
        valid, rejected = wireless.validate_channels(self._parse_channels(channels_spec))
        if rejected:
            self._log.info(
                "activity: excluding non-IEEE channels %s", rejected
            )
        # Scan only channels the card can tune, so a 2.4 GHz-only radio doesn't
        # waste the scan dwelling on 5 GHz channels it cannot set.
        supported = set(wireless.supported_channels(interface))
        valid = [c for c in valid if c in supported]
        if not valid:
            raise ValueError("No valid IEEE 802.11 channels to scan.")

        try:
            original = wireless.current_channel(interface)
        except ModuleError:
            original = None

        ok_rows: list[dict] = []
        failed_rows: list[dict] = []
        try:
            for channel in valid:
                try:
                    wireless.set_channel(interface, channel)
                except wireless.WirelessError as exc:
                    # A channel that won't tune is a finding, not noise: show it
                    # so a radio pinned to one channel is visible at a glance.
                    self._log.debug(
                        "activity: channel %d on %s failed: %s", channel, interface, exc
                    )
                    failed_rows.append({
                        "channel": channel, "frames": "-", "beacons": "-",
                        "bytes": "-", "status": "tune failed (radio busy?)",
                    })
                    continue
                packets = scapy_io.sniff(interface, timeout=max(dwell_ms / 1000.0, 0.01))
                beacons = 0
                byte_total = 0
                for packet in packets:
                    if packet.dot11_info().get("subtype") == "beacon":
                        beacons += 1
                    try:
                        byte_total += len(packet.build())
                    except Exception:  # noqa: BLE001 - never let one frame abort the scan
                        pass
                ok_rows.append({
                    "channel": channel,
                    "frames": len(packets),
                    "beacons": beacons,
                    "bytes": byte_total,
                    "status": "ok",
                })
        finally:
            if original is not None:
                try:
                    wireless.set_channel(interface, original)
                except ModuleError:
                    pass

        ok_rows.sort(key=lambda row: (row["frames"], row["bytes"]), reverse=True)
        return ok_rows + failed_rows, rejected

    def radio_hint(self, interface: str) -> str:
        """A one-line, actionable reason a channel change is being refused.

        Names the sibling interface(s) holding the radio when there are any -
        the usual cause of 'device busy' when tuning - and points at the fix.
        """
        siblings = wireless.phy_siblings(interface)
        if siblings:
            others = ", ".join(f"{dev} ({mode})" for dev, mode in siblings)
            return (
                f"this radio is shared with {others}; a connection manager holding "
                "it pins the channel. Run 'sudo airmon-ng check kill' first."
            )
        return (
            "the channel would not change (device busy) - run 'sudo airmon-ng "
            "check kill' to release the radio from NetworkManager/wpa_supplicant."
        )

    # --- Session views --------------------------------------------------------

    def summary(self) -> dict:
        with self._lock:
            self._reap_locked()
            packets = list(self.packets)
            capturing = self._sniffer is not None
            active_filters = len(self.filters)
        if not packets:
            return {"frames": 0, "active_filters": active_filters, "capturing": capturing}
        bssids: set[str] = set()
        ssids: set[str] = set()
        subtypes: dict[str, int] = {}
        for packet in packets:
            info = packet.dot11_info()
            if info.get("bssid"):
                bssids.add(info["bssid"])
            if info.get("ssid") and info["ssid"] != "<hidden>":
                ssids.add(info["ssid"])
            label = f"{info.get('type', '-')}/{info.get('subtype', '-')}"
            subtypes[label] = subtypes.get(label, 0) + 1
        return {
            "frames": len(packets),
            "unique_bssids": len(bssids),
            "unique_ssids": len(ssids),
            "frame_types": ", ".join(f"{k}={v}" for k, v in sorted(subtypes.items())),
            "active_filters": active_filters,
            "capturing": capturing,
        }

    def networks(self) -> list[dict]:
        """Access points seen, aggregated from beacons/probe responses."""
        with self._lock:
            packets = list(self.packets)
        aps: dict[str, dict] = {}
        for packet in packets:
            info = packet.dot11_info()
            if info.get("subtype") not in ("beacon", "probe-resp"):
                continue
            bssid = info.get("bssid")
            if not bssid:
                continue
            ap = aps.setdefault(bssid, {
                "bssid": bssid, "ssid": "-", "channel": "-", "signal": "-", "beacons": 0,
            })
            if info.get("subtype") == "beacon":
                ap["beacons"] += 1
            ssid = info.get("ssid")
            if ssid and ssid != "<hidden>":
                ap["ssid"] = ssid
            elif ap["ssid"] == "-" and ssid == "<hidden>":
                ap["ssid"] = "<hidden>"
            if info.get("channel") is not None:
                ap["channel"] = info["channel"]
            if info.get("signal") is not None:
                ap["signal"] = info["signal"]
        return sorted(aps.values(), key=lambda ap: ap["beacons"], reverse=True)

    def stations(self) -> list[dict]:
        """Client stations seen, with the AP they talk to (from data/probe frames)."""
        with self._lock:
            packets = list(self.packets)
        # Frames that don't identify a client transmitter (AP-originated or
        # address-less control frames) are skipped.
        skip = {"beacon", "probe-resp", "ack", "cts", "rts", "ba", "bar",
                "cf-end", "cf-end-ack"}
        stations: dict[str, dict] = {}
        for packet in packets:
            info = packet.dot11_info()
            if info.get("subtype") in skip:
                continue
            transmitter = info.get("transmitter")
            bssid = info.get("bssid")
            if not transmitter or transmitter == "ff:ff:ff:ff:ff:ff":
                continue
            if transmitter == bssid:  # frame from the AP itself, not a client
                continue
            station = stations.setdefault(transmitter, {
                "station": transmitter, "bssid": "-", "frames": 0, "signal": "-",
            })
            station["frames"] += 1
            # Prefer a real AP BSSID over the broadcast address a probe request
            # carries, and don't let broadcast overwrite a known association.
            if (
                bssid
                and bssid != "ff:ff:ff:ff:ff:ff"
                and station["bssid"] in ("-", "ff:ff:ff:ff:ff:ff")
            ):
                station["bssid"] = bssid
            if info.get("signal") is not None:
                station["signal"] = info["signal"]
        return sorted(stations.values(), key=lambda s: s["frames"], reverse=True)

    def inspect_rows(self) -> list[dict]:
        with self._lock:
            packets = list(self.packets)
        rows: list[dict] = []
        for packet in packets:
            info = packet.dot11_info()

            def part(key: str) -> str:
                value = info.get(key)
                return "-" if value in (None, "") else str(value)

            rows.append({
                "timestamp": packet.timestamp(),
                "subtype": f"{part('type')}/{part('subtype')}",
                "transmitter": part("transmitter"),
                "receiver": part("receiver"),
                "bssid": part("bssid"),
                "ssid": part("ssid"),
            })
        return rows

    # --- Helpers --------------------------------------------------------------

    def _require_monitor(self, interface: str) -> str:
        """Validate ``interface`` is a monitor-mode 802.11 NIC; return it stripped."""
        interface = (interface or "").strip()
        if not interface:
            raise ValueError("Specify the monitor-mode interface.")
        if not wireless.is_wireless(interface):
            raise ModuleError(f"{interface!r} is not a wireless interface.")
        mode = wireless.current_mode(interface)
        if mode != "monitor":
            raise ModuleError(
                f"{interface!r} is in {mode!r} mode; run "
                f"'interface mode {interface} monitor' first."
            )
        return interface

    @staticmethod
    def _parse_channels(spec: str) -> list[int]:
        """Parse a channel spec: a number, a comma list, a range, or ``all``."""
        spec = spec.strip().lower()
        if spec == "all":
            return wireless.ieee_channels()
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

    # --- Filters --------------------------------------------------------------

    def add_filters(
        self, action: str, field_values: dict[str, str | None]
    ) -> list[WirelessFilter]:
        action = action.lower()
        if action not in ACTIONS:
            raise ValueError(
                f"Action must be one of {', '.join(ACTIONS)} (got {action!r})."
            )
        provided = [(f, field_values.get(f)) for f in FIELDS if field_values.get(f)]
        if not provided:
            raise ValueError(
                "Provide at least one field to filter on "
                f"({', '.join('--' + f for f in FIELDS)})."
            )
        created: list[WirelessFilter] = []
        with self._lock:
            for field, raw in provided:
                for value in split_values(raw):
                    self._validate_value(field, value)
                    entry = WirelessFilter(self._next_id, action, field, value)
                    self._next_id += 1
                    self.filters.append(entry)
                    created.append(entry)
        self._log.info("Added %d %s wireless filter(s)", len(created), action)
        return created

    def remove_filters(self, spec: str) -> list[WirelessFilter]:
        spec = spec.strip()
        with self._lock:
            if spec.lower() == "all":
                removed = list(self.filters)
                self.filters.clear()
                if not removed:
                    raise ModuleError("There are no filters to remove.")
                return removed
            ids: set[int] = set()
            for token in split_values(spec):
                if not token.isdigit():
                    raise ValueError(f"Invalid filter id {token!r}; expected a number.")
                ids.add(int(token))
            removed = [f for f in self.filters if f.id in ids]
            if not removed:
                raise ModuleError(f"No filters match id(s): {spec}.")
            self.filters = [f for f in self.filters if f.id not in ids]
            self._log.info("Removed %d wireless filter(s)", len(removed))
            return removed

    def list_filters(self) -> list[dict]:
        with self._lock:
            return [f.as_row() for f in self.filters]

    @staticmethod
    def _validate_value(field: str, value: str) -> None:
        if field == "type" and value.lower() not in TYPE_NAMES:
            raise ValueError(
                f"Unknown type {value!r}. Supported: {', '.join(TYPE_NAMES)}."
            )
        if field == "subtype" and value.lower() not in SUBTYPE_NAMES:
            raise ValueError(
                f"Unknown subtype {value!r}. Supported: {', '.join(sorted(SUBTYPE_NAMES))}."
            )
        if field == "bssid":
            MacAddress.parse(value)  # raises ValueError on a malformed address

"""Shared monitor-mode radio lifecycle for the wireless services.

Both wireless services need the *same* "quiet, reversible" monitor-mode plumbing:
resolve a target to an interface/PHY, put the radio into monitor mode (recording
exactly how to undo it), and restore it on the way out - route-preservation style.
:class:`~mac_and_seize.modules.wireless.capture.WirelessCaptureService` needs it
to *receive* frames; :class:`~mac_and_seize.modules.wireless.beacon.BeaconService`
needs it to *inject* them. Rather than duplicate ~100 lines, that lifecycle lives
here as a mixin both services inherit.

Contract for the concrete class: provide ``self._log`` (a logger). The mixin owns
``self._monitor_undo`` (how to restore the radio) and ``self._teardown_note`` (the
last restore message); both have safe class-level defaults, so a subclass need not
initialise them. The mixin never touches capture/beacon state, only the radio.
"""

from __future__ import annotations

from mac_and_seize.core.errors import ModuleError
from mac_and_seize.net.adapters import scapy_io, wireless


class MonitorRadioMixin:
    """Resolve a target radio, switch it to monitor mode, and restore it later."""

    # How to restore the radio when we are done (route-preservation style): set by
    # _ensure_monitor, consumed by _teardown_monitor. Class-level defaults so a
    # subclass that never enters monitor mode still reads a sane value.
    _monitor_undo: dict | None = None
    _teardown_note: str = ""

    def _resolve_target(self, target: str) -> tuple[str, str]:
        """Resolve ``target`` to ``('iface', name)`` or ``('phy', phy)``.

        ``target`` may be a wireless interface, a PHY (``phy0``), or empty to
        auto-pick the sole radio - its interface if it has exactly one, else the
        PHY itself (the case after iwd was stopped and ``wlan0`` disappeared).
        """
        target = (target or "").strip()
        if target:
            if wireless.is_wireless(target):
                return ("iface", target)
            if target in wireless.list_phys():
                return ("phy", target)
            raise ModuleError(
                f"{target!r} is not a wireless interface or PHY. Pass a wireless "
                "interface (e.g. wlan0), a PHY (e.g. phy0), or nothing to use the "
                "only radio."
            )
        phys = wireless.list_phys()
        if not phys:
            raise ModuleError("No wireless radios found on this system.")
        if len(phys) > 1:
            raise ModuleError(
                f"Several radios present ({', '.join(phys)}); name the interface "
                "or PHY to capture on."
            )
        ifaces = wireless.interfaces_on_phy(phys[0])
        if len(ifaces) == 1:
            return ("iface", ifaces[0][0])
        if not ifaces:
            return ("phy", phys[0])
        raise ModuleError(
            f"Several interfaces on {phys[0]} "
            f"({', '.join(dev for dev, _ in ifaces)}); name the one to capture on."
        )

    def _ensure_monitor(self, target: str | None) -> str:
        """Return a monitor-mode interface for ``target``, preparing one if needed.

        Does the setup quietly and records how to undo it (:meth:`_teardown_monitor`)
        so stopping restores the radio - route-preservation style:

        * an interface already in monitor mode is used as-is (left untouched);
        * a managed interface is switched to monitor (reverted on stop);
        * an idle PHY gets a fresh monitor VIF (removed on stop).

        It never stops a connection manager itself: if one is holding the radio it
        raises with the command to free it, rather than fighting it or dropping
        the link uncleanly.
        """
        kind, ref = self._resolve_target(target)
        if kind == "iface":
            mode = wireless.current_mode(ref)
            if mode == "monitor":
                self._monitor_undo = None
                return ref
            holders = wireless.interfering_daemons()
            if holders:
                raise ModuleError(
                    f"{ref} is in {mode} mode and {', '.join(holders)} is holding "
                    "the radio; switching it to monitor now would be fought and "
                    "would drop your connection uncleanly. Free the radio first "
                    f"('sudo systemctl stop {holders[0]}' or 'sudo airmon-ng check "
                    "kill'), then try again."
                )
            wireless.set_mode(ref, "monitor")
            self._monitor_undo = {"action": "revert", "iface": ref, "prev": mode}
            # Re-typing changes the link layer scapy caches for this NIC.
            scapy_io.refresh_interfaces()
            return ref
        iface = wireless.add_monitor(ref)
        self._monitor_undo = {"action": "delete", "iface": iface, "phy": ref}
        # A just-created interface is absent from scapy's import-time cache;
        # without this refresh sniffing on it fails with ENODEV (No such device).
        scapy_io.refresh_interfaces()
        return iface

    def _teardown_monitor(self, *, note: bool = True) -> None:
        """Undo whatever :meth:`_ensure_monitor` changed; optionally record a note.

        Best-effort: a teardown failure is logged and surfaced but never masks the
        stop. ``note=False`` for a transient use (e.g. an activity scan) that
        restores the radio silently.
        """
        undo, self._monitor_undo = self._monitor_undo, None
        if not undo:
            return
        try:
            if undo["action"] == "revert":
                wireless.set_mode(undo["iface"], undo["prev"])
                message = f" {undo['iface']} restored to {undo['prev']} mode."
            else:  # delete a VIF we created
                wireless.del_interface(undo["iface"])
                message = (
                    f" Removed monitor interface {undo['iface']}; restart your "
                    "connection manager to reconnect."
                )
        except Exception as exc:  # noqa: BLE001 - teardown must not mask the stop
            message = f" WARNING: could not restore {undo['iface']} automatically: {exc}"
            self._log.warning("Monitor teardown failed for %s: %s", undo.get("iface"), exc)
        if note:
            self._teardown_note = message

    def pop_teardown_note(self) -> str:
        """Return and clear the note describing the last monitor teardown, if any."""
        note, self._teardown_note = self._teardown_note, ""
        return note

    def radio_hint(self, interface: str | None = None) -> str:
        """A one-line, actionable reason a channel change is being refused.

        Names whatever is most likely holding the radio: a sibling interface on
        the same PHY (only checkable when ``interface`` is given and still
        exists), or a running connection manager (the usual cause on a
        single-interface card, where there is no sibling to point at). Falls back
        to the driver-can't-retune case (e.g. Realtek rtw88 in monitor mode).
        """
        siblings = wireless.phy_siblings(interface) if interface else []
        if siblings:
            others = ", ".join(f"{dev} ({mode})" for dev, mode in siblings)
            return (
                f"this radio is shared with {others}; a connection manager holding "
                "it pins the channel. Run 'sudo airmon-ng check kill' first."
            )
        daemons = wireless.interfering_daemons()
        if daemons:
            return (
                f"{', '.join(daemons)} is running and holds the radio on its "
                "associated channel. Run 'sudo airmon-ng check kill' (or 'sudo "
                f"systemctl stop {daemons[0]}') and retry."
            )
        return (
            "the radio would not change channel. Either a connection manager is "
            "holding it (run 'sudo airmon-ng check kill'), or the driver cannot "
            "retune in monitor mode (common on Realtek rtw88 cards)."
        )

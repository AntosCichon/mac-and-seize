"""DHCP automations (not implemented yet).

Skeleton area of the :mod:`mac_and_seize.modules.l2` module. It contributes no
commands yet - only a staged group description that activates once actions are
added here. To implement it, mirror the ``mac`` area: add ``service.py`` /
``actions.py`` and return the actions from :func:`build_actions` (and populate
``SERVICES`` if the area needs a session-scoped service).
"""

from __future__ import annotations

#: Service key -> zero-arg factory. None yet.
SERVICES: dict = {}

#: Staged label; the ``l2 dhcp`` group appears once this area has commands.
GROUP_DESCRIPTIONS = {
    "l2.dhcp": "DHCP automations (not implemented yet)",
}


def build_actions() -> list:
    """No commands yet; see the module docstring to implement this area."""
    return []

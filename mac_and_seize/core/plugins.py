"""Module discovery - the heart of the plugin system.

Every feature lives in its own package under :mod:`mac_and_seize.modules`. A
module is registered *only* by existing there and exposing a ``register()``
function that returns a :class:`ModuleSpec`; no shared file needs editing to add
one. :class:`~mac_and_seize.core.context.AppContext` calls
:func:`discover_modules` once at startup, instantiates each module's services,
and collects its actions and group descriptions.

See ``mac_and_seize/modules/README.md`` for the authoring guide.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Callable

from mac_and_seize.core.actions import Action
from mac_and_seize.observability import get_logger

logger = get_logger(__name__)


@dataclass
class ModuleSpec:
    """What a module contributes to the application.

    Attributes
    ----------
    name:
        Human-readable module name, used in logs and for stable ordering.
    services:
        Mapping of ``service key -> zero-arg factory``. Each factory is called
        once per :class:`AppContext` and the instance is stored under its key;
        action handlers fetch it with ``context.service(key)``. Keys must be
        unique across all modules.
    actions:
        The operations the module exposes (see :class:`Action`). Their dotted
        names determine where they appear in the command tree.
    group_descriptions:
        Optional ``"dotted.group": "description"`` labels shown in help for the
        module's command groups.
    order:
        Sort key controlling display/registration order across modules (lower
        first; ties broken by ``name``). Defaults to ``100``.
    """

    name: str
    services: dict[str, Callable[[], object]] = field(default_factory=dict)
    actions: list[Action] = field(default_factory=list)
    group_descriptions: dict[str, str] = field(default_factory=dict)
    order: int = 100


def discover_modules() -> list[ModuleSpec]:
    """Import every package under ``mac_and_seize.modules`` and register it.

    A subpackage participates by exposing a top-level ``register() ->
    ModuleSpec``. Packages without one are skipped with a warning; a module that
    raises during registration is skipped (logged) so one bad module cannot take
    down the whole app. The result is sorted by ``(order, name)``.
    """
    import mac_and_seize.modules as package

    specs: list[ModuleSpec] = []
    for info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        try:
            module = importlib.import_module(info.name)
        except Exception:  # noqa: BLE001 - never let one module break discovery
            logger.exception("Failed to import module %s; skipping", info.name)
            continue

        register = getattr(module, "register", None)
        if not callable(register):
            logger.warning("Module %s has no register(); skipping", info.name)
            continue

        try:
            spec = register()
        except Exception:  # noqa: BLE001
            logger.exception("Module %s failed to register; skipping", info.name)
            continue

        specs.append(spec)

    specs.sort(key=lambda spec: (spec.order, spec.name))
    logger.info("Discovered %d module(s): %s", len(specs), [s.name for s in specs])
    return specs

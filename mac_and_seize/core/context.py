"""The application context passed explicitly through the app (no globals).

The previous design relied on module-level singletons (``_config``, ``_timer``)
and lazily parsed ``sys.argv`` from deep inside ``get_config()``. That is
replaced by an :class:`AppContext` that is built once at startup (in the Typer
callback) and threaded through commands via ``ctx.obj``. The web interface will
build its own :class:`AppContext` the same way.

The context is populated entirely from *discovered modules* (see
:mod:`mac_and_seize.core.plugins`): it does not import or name any feature
module directly, so adding a module requires no change here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from mac_and_seize.config import AppConfig
from mac_and_seize.core.actions import Action
from mac_and_seize.core.plugins import discover_modules
from mac_and_seize.core.tasks import TaskManager


class Timer:
    """Tracks wall-clock runtime and named measurement checkpoints."""

    def __init__(self, timezone_offset: int = 0):
        self.timezone = timezone(timedelta(hours=timezone_offset))
        self.start_time = datetime.now(self.timezone)
        self._measure: list[datetime] = []

    def stamp(self) -> datetime:
        return datetime.now(self.timezone)

    def runtime(self, fmt: str = "seconds", reference: int | None = None) -> str:
        start = self.start_time if reference is None else self._measure[reference]
        delta = (self.stamp() - start).total_seconds()
        if fmt == "seconds":
            return "%.2f" % delta
        if fmt == "time":
            s = int(delta)
            return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"
        return str(delta)

    def start_measure(self) -> int:
        self._measure.append(self.stamp())
        return len(self._measure) - 1


@dataclass
class AppContext:
    """Holds shared, per-run state and the module-provided services/actions."""

    config: AppConfig
    timer: Timer
    services: dict[str, object] = field(init=False)
    actions: list[Action] = field(init=False)
    group_descriptions: dict[str, str] = field(init=False)
    tasks: TaskManager = field(init=False)
    #: Full invocation string of the command currently running (set by the
    #: front-end before a handler runs), so background tasks can record exactly
    #: what was invoked. Empty when no command is executing.
    current_command: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.services = {}
        self.actions = []
        self.group_descriptions = {}
        self.tasks = TaskManager(self.timer.timezone)
        for spec in discover_modules():
            for key, factory in spec.services.items():
                if key in self.services:
                    raise RuntimeError(
                        f"Service key {key!r} from module {spec.name!r} collides "
                        "with another module's service."
                    )
                self.services[key] = factory()
            self.actions.extend(spec.actions)
            self.group_descriptions.update(spec.group_descriptions)

    def service(self, key: str) -> object:
        """Return a registered service instance by key (raises if unknown)."""
        try:
            return self.services[key]
        except KeyError:
            raise KeyError(
                f"No service registered under {key!r}. "
                f"Registered: {sorted(self.services)}"
            ) from None

    @classmethod
    def create(cls, config: AppConfig) -> "AppContext":
        return cls(config=config, timer=Timer(config.setup.timezone_offset))

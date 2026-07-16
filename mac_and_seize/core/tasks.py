"""Background-task registry - shared infrastructure for long-running work.

The interactive session runs on a single thread that reads commands. Some
actions (packet capture, long scans, ...) must keep running *while the user
keeps typing*, so they spawn their own worker thread and register a
:class:`Task` here. The top-level ``tasks`` command lists whatever is currently
running.

This lives in ``core`` so it is available to every module through
``context.tasks`` (see :class:`~mac_and_seize.core.context.AppContext`). A module
starts background work with::

    task = context.tasks.start(context.current_command, stop=my_stop_callable)
    ...
    context.tasks.finish(task)   # or task.stop() to signal the worker

No shared file needs editing to add a new background-capable module - the
registry is generic and the worker/threading lives inside the module.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


def _format_hms(seconds: float) -> str:
    """Render a duration as ``HH:MM:SS``."""
    total = int(seconds)
    return f"{total // 3600:02d}:{(total % 3600) // 60:02d}:{total % 60:02d}"


@dataclass
class Task:
    """A unit of background work tracked by :class:`TaskManager`.

    ``command`` is the full invocation that started it (e.g.
    ``"capture start --time 60"``), recorded so ``tasks`` can show exactly what
    was run regardless of the context the user was in. ``stop`` is an optional
    callable the owner provides so the task can be asked to stop.
    """

    id: int
    command: str
    started_at: datetime
    stop: Optional[Callable[[], None]] = None
    _running: bool = field(default=True, repr=False)

    def is_running(self) -> bool:
        return self._running

    def runtime(self, *, now: datetime | None = None) -> str:
        reference = now or datetime.now(self.started_at.tzinfo)
        return _format_hms((reference - self.started_at).total_seconds())

    def started(self) -> str:
        return self.started_at.strftime("%H:%M:%S")


class TaskManager:
    """Thread-safe registry of running background tasks."""

    def __init__(self, tzinfo: timezone | None = None) -> None:
        self._tzinfo = tzinfo or timezone.utc
        self._lock = threading.Lock()
        self._tasks: dict[int, Task] = {}
        self._next_id = 1

    def start(
        self, command: str, *, stop: Callable[[], None] | None = None
    ) -> Task:
        """Register a new running task and return it."""
        with self._lock:
            task = Task(
                id=self._next_id,
                command=command or "(unknown)",
                started_at=datetime.now(self._tzinfo),
                stop=stop,
            )
            self._tasks[task.id] = task
            self._next_id += 1
            return task

    def finish(self, task: Task) -> None:
        """Mark a task finished and drop it from the running set (idempotent)."""
        with self._lock:
            task._running = False
            self._tasks.pop(task.id, None)

    def running(self) -> list[Task]:
        """Snapshot of currently-running tasks, oldest first."""
        with self._lock:
            return sorted(self._tasks.values(), key=lambda t: t.id)

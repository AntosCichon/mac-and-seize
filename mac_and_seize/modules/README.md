# Writing a module

This directory holds **feature modules**. Each module is a self-contained Python
package in its own folder. A module is wired into the whole application — the
interactive CLI, tab-completion, help, and the future web UI — **just by
existing here and exposing a `register()` function**. You never edit any shared
file to add a module.

> Audience: this guide is written to be followed with no other context about the
> codebase. If you only read one file, read this one, then copy the
> `interface/` or `capture/` module as a template.

---

## 1. How discovery works

At startup, `mac_and_seize/core/context.py` (`AppContext`) calls
`discover_modules()` from `mac_and_seize/core/plugins.py`. That function:

1. Iterates over every subpackage directly under `mac_and_seize/modules/`.
2. Imports each one and looks for a top-level callable `register()`.
3. Calls `register()`, expecting a `ModuleSpec` back.
4. Sorts all specs by `(order, name)` and returns them.

`AppContext` then, for every spec:

- instantiates each service factory and stores it in `context.services[key]`,
- appends the spec's actions to `context.actions`,
- merges the spec's group descriptions into `context.group_descriptions`.

A module that has no `register()`, or whose `register()` raises, is skipped with
a log warning — it cannot crash the app or other modules.

**Consequence:** to add a feature you only create files inside a new folder
here. To remove one, delete its folder. Nothing else changes.

---

## 2. Required layout

```
mac_and_seize/modules/
  <your_module>/
    __init__.py     # MUST define register() -> ModuleSpec
    service.py      # your business logic (a plain class)
    actions.py      # Action definitions + thin handlers
    <anything>.py   # e.g. net.py, hardware.py — your internals
```

Only `__init__.py` with `register()` is strictly required; the `service.py` /
`actions.py` split is the convention used by existing modules and keeps handlers
thin. Put all private helpers, system calls, and third-party imports inside your
module folder — do **not** add code to `core/` or `cli/`.

---

## 3. The `register()` contract

`__init__.py` must expose `register() -> ModuleSpec`. `ModuleSpec` is defined in
`mac_and_seize/core/plugins.py`:

```python
@dataclass
class ModuleSpec:
    name: str                                   # module name (logs + ordering)
    services: dict[str, Callable[[], object]]   # service key -> zero-arg factory
    actions: list[Action]                       # commands this module exposes
    group_descriptions: dict[str, str]          # "dotted.group" -> help label
    order: int = 100                            # lower sorts first across modules
```

Field-by-field:

- **`name`** — a short identifier, e.g. `"bluetooth"`. Used in logs and to break
  `order` ties.
- **`services`** — maps a **globally-unique key** to a **factory** (usually just
  the service class, since classes are zero-arg callables here). Each factory is
  called **once per `AppContext`**; the instance is fetched by handlers via
  `context.service(key)`. If two modules register the same key the app raises at
  startup — pick a key namespaced to your module (e.g. `"bluetooth"`).
- **`actions`** — the list of `Action`s (see §4). Order within the list is the
  display order within your module.
- **`group_descriptions`** — optional labels for your command groups (see §6).
- **`order`** — controls where your module's groups/commands appear relative to
  other modules. Existing modules use `interface=10`, `capture=20`. Default 100.

---

## 4. Actions and parameters

`Action` and `Param` come from `mac_and_seize/core/actions.py`:

```python
@dataclass
class Param:
    name: str            # value key handed to your handler
    help: str            # one-line description shown in help
    type: type = str     # str or int (int is parsed/validated for you)
    required: bool = True
    default: Any = None  # used when an optional param is omitted
    multiple: bool = False  # accept a list/range; handler runs once per value
    is_flag: bool = False   # a `--name` switch that takes no value (see §4.4)

@dataclass
class Action:
    name: str            # DOTTED PATH -> command tree location (see below)
    title: str           # short label in listings
    description: str     # full text in `<cmd> help`
    handler: Callable[[AppContext, dict], Any]
    params: list[Param] = []
    examples: list[str] = []
    requires_root: bool = False
```

### 4.1 Dotted names build the command tree

`Action.name` is a dotted path. Every segment **before the last** is a (nested)
group; the **last** segment is the command:

| `Action.name`              | CLI command                | Tree location                 |
| -------------------------- | -------------------------- | ----------------------------- |
| `"capture"`                | `capture ...`              | top-level command             |
| `"bluetooth.scan"`         | `bluetooth scan`           | group `bluetooth` → `scan`    |
| `"bluetooth.device.pair"`  | `bluetooth device pair`    | `bluetooth` → `device` → `pair` |

Groups are created implicitly from the names — you do not declare them. Nesting
depth is unlimited. In the CLI, typing a group name (`bluetooth`) enters that
context; `back` leaves it; commands resolve against the current context first,
then fall back to the top level.

### 4.2 Handler signature and return values

```python
def handler(context: AppContext, values: dict) -> Any: ...
```

- `values` is `{param.name: parsed_value}`. Required params are positional in the
  CLI; optional params are passed as `--name value`. `int` params arrive already
  converted; missing optional params arrive as their `default`.
- Keep handlers **thin**: fetch your service, call it, return plain data. Do not
  print, and do not put business logic in the handler.
- Return types are rendered generically by every front-end:
  - `str` → shown as a success line.
  - `dict` → a two-column key/value table.
  - `list[dict]` → a table (keys become columns).
  - `list[str]` (or other) → a numbered list.
  - `None` → nothing.

### 4.3 `multiple` — list and range arguments

Set `multiple=True` on a param to let the user pass a **collection** in one
token. The CLI accepts:

- **Lists** — comma-separated values: `eth0,eth1,eth2`.
- **Ranges** — inclusive integer ranges `a-b`: `1-3` → `1,2,3` (descending
  ranges like `3-1` also work). Ranges may be mixed into a list: `1-3,7`.
- **A single value** — treated as a one-item collection.

Values are converted with the param's `type` (so `int` ranges arrive as ints)
and, for ranges, expanded before your handler sees them. **Your handler stays
written for a single value:** the front-end fans out and calls it once per
value (the cartesian product when several params are `multiple`), then
aggregates the results — `list[dict]` returns merge into one table, `str`
returns into one numbered list. If a value fails, its error is reported and the
remaining values still run.

```python
# handler is unchanged; it only ever sees one name
Param("name", "Interface name (e.g. eth0)", multiple=True)
# CLI: "interface state up eth0,eth1"  -> handler runs for eth0, then eth1
```

Use `multiple=True` only when running the action per-value is safe. Avoid it for
"replace"-style operations (e.g. an address `set` that flushes first), where
looping would undo earlier values.

### 4.4 `is_flag` — boolean switches

Set `is_flag=True` on an **optional** param to make it a plain switch instead
of a `--name value` option: it takes no value on the command line, arrives as
`True` when the user passes `--name`, and as its `default` (normally `False`)
when they don't.

```python
Param("no-preserve", "Skip restoring routes dropped by the change",
      bool, required=False, default=False, is_flag=True)
# CLI: "interface mac eth0 <mac>"                 -> {"no-preserve": False}
# CLI: "interface mac eth0 <mac> --no-preserve"    -> {"no-preserve": True}
```

Use a hyphenated `name` (`"no-preserve"`, not `"no_preserve"`) if that's the
CLI spelling you want — the CLI flag is `--<param.name>` verbatim, and the same
string is the key in `values`, so the handler reads `values["no-preserve"]`.

### 4.5 `requires_root`

Set `requires_root=True` for anything that needs elevated privileges. The CLI
**blocks** the action with a helpful message when not running as root (the user
can relaunch with the built-in `sudo` command), and colours it red in help. You
do not check privileges yourself.

### 4.6 `examples`

Each string is shown verbatim under `Examples:` in `<cmd> help`. Write them as
full command lines, e.g. `"bluetooth device pair AA:BB:CC:DD:EE:FF"`.

---

## 5. Services and accessing them

A service is a plain class holding your logic and (optionally) a logger. It is
instantiated once and shared. Handlers fetch it by key:

```python
service = context.service("bluetooth")   # the instance your factory produced
```

Get a logger with `from mac_and_seize.observability import get_logger` and
`self._log = get_logger(__name__)`. Logging is already configured by the app.

---

## 6. Group descriptions

`group_descriptions` maps a **dotted group path** to the label shown next to that
group in help. Only groups (not commands) use these:

```python
group_descriptions = {
    "bluetooth": "Discover and manage Bluetooth devices",
    "bluetooth.device": "Operate on a specific device",
}
```

Groups without an entry fall back to the generic label `"commands"`.

---

## 7. Error handling

Raise, don't print. Two exception types are caught by every front-end and shown
as a clean one-line message (the session stays alive):

- **`ValueError`** — for bad **user input** (malformed address, unknown option
  value, etc.).
- **`mac_and_seize.core.errors.ModuleError`** (or a subclass) — for expected
  **operational** failures (device missing, external command failed, wrong
  state). Define your own subclass if you want a specific type:

  ```python
  from mac_and_seize.core.errors import ModuleError
  class BluetoothError(ModuleError): ...
  ```

`OSError` is also caught (e.g. permission errors from syscalls). Anything else
is treated as an unexpected bug: it's logged with a traceback and the session
continues.

---

## 8. Dependencies

If your module needs a third-party package, add it to `[project.dependencies]`
in the repo-root `pyproject.toml` and install it (`uv add <pkg>` /
`uv sync`). Import it **inside your module** only.

---

## 9. Stateful services & background tasks

### Session state
A service is instantiated **once per `AppContext`** and lives for the whole
session, so it is the right place to keep state that must persist across
commands (a list of results, cached handles, configuration built up over
several commands). Store it on the instance (`self.items = []`) and mutate it
from your handlers. If a background thread touches that state, guard it with a
`threading.Lock`. The `capture` module does exactly this: it accumulates
captured packets and filters on the service across many commands.

### Long-running / background work
Some actions must keep running while the user keeps typing (a capture, a long
scan). Do **not** block the handler; instead spawn your own worker (a thread, or
a library helper like scapy's `AsyncSniffer`) and register it with the shared
task registry so it shows up in the top-level `tasks` command:

```python
def _start(context, values):
    service = context.service("mymodule")
    # context.current_command is the full invocation, e.g. "mymodule start --time 60",
    # recorded by the front-end regardless of the current context.
    task = context.tasks.start(context.current_command, stop=service.stop)
    service.begin(...)                # kicks off the worker thread
    return "Started in the background."

def _stop(context, values):
    context.service("mymodule").stop()   # your stop() calls context.tasks.finish(task)
    return "Stopped."
```

`context.tasks` (a `TaskManager` from `mac_and_seize/core/tasks.py`) offers:

- `start(command, stop=None) -> Task` — register a running task; `stop` is an
  optional zero-arg callable used to ask the task to stop.
- `finish(task)` — mark it done and drop it from the running set (call this when
  the work actually ends, e.g. inside your `stop()`).
- `running() -> list[Task]` — what the `tasks` command lists.

Because the REPL is single-threaded, **do not print from a worker thread** (it
corrupts the prompt). Return data from the command that *reads* the results
(`stop`, `summary`, ...) instead, and finalize self-stopped work lazily on the
next command. All of this uses only `context.tasks` / `context.current_command`
— no shared file is edited to add a background-capable module.

---

## 10. Complete worked example: a `bluetooth` module

Create `mac_and_seize/modules/bluetooth/` with the four files below. After
saving them, run the app — `bluetooth` appears in `help` automatically.

### `bluetooth/hardware.py` — low-level calls (your internals)

```python
"""Thin wrappers over `bluetoothctl` (argument lists, never a shell string)."""
from __future__ import annotations
import subprocess
from mac_and_seize.core.errors import ModuleError


class BluetoothError(ModuleError):
    """A bluetoothctl command failed or is unavailable."""


def _run(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["bluetoothctl", *args], check=True, capture_output=True, text=True
        )
    except FileNotFoundError as exc:
        raise BluetoothError("`bluetoothctl` not found; is BlueZ installed?") from exc
    except subprocess.CalledProcessError as exc:
        raise BluetoothError((exc.stderr or "").strip() or "command failed") from exc
    return proc.stdout


def scan(seconds: int) -> list[dict]:
    out = _run(["--timeout", str(seconds), "scan", "on"])
    devices = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "Device":
            devices.append({"mac": parts[2], "name": " ".join(parts[3:]) or "-"})
    return devices


def pair(mac: str) -> None:
    _run(["pair", mac])
```

### `bluetooth/service.py` — business logic + validation

```python
"""Bluetooth operations shared by all front-ends."""
from __future__ import annotations
import re
from mac_and_seize.modules.bluetooth import hardware
from mac_and_seize.observability import get_logger

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


class BluetoothService:
    def __init__(self) -> None:
        self._log = get_logger(__name__)

    def scan(self, seconds: int) -> list[dict]:
        if seconds <= 0:
            raise ValueError("Scan duration must be a positive number of seconds.")
        self._log.info("Scanning for %ds", seconds)
        return hardware.scan(seconds)

    def pair(self, mac: str) -> str:
        if not _MAC_RE.match(mac.strip()):
            raise ValueError(f"Invalid device address {mac!r}.")
        hardware.pair(mac.strip())
        self._log.info("Paired with %s", mac)
        return mac.strip()
```

### `bluetooth/actions.py` — commands + thin handlers

```python
"""Actions exposed by the bluetooth module."""
from __future__ import annotations
from typing import TYPE_CHECKING
from mac_and_seize.core.actions import Action, Param

if TYPE_CHECKING:
    from mac_and_seize.core.context import AppContext

SERVICE = "bluetooth"

GROUP_DESCRIPTIONS = {
    "bluetooth": "Discover and manage Bluetooth devices",
    "bluetooth.device": "Operate on a specific device",
}


def _scan(context: "AppContext", values: dict) -> list[dict]:
    return context.service(SERVICE).scan(values["seconds"])


def _pair(context: "AppContext", values: dict) -> str:
    mac = context.service(SERVICE).pair(values["mac"])
    return f"Paired with {mac}"


def build_actions() -> list[Action]:
    return [
        Action(
            "bluetooth.scan",
            "Scan for devices",
            "Discover nearby Bluetooth devices (requires root).",
            _scan,
            [Param("seconds", "How long to scan for", int, required=False, default=10)],
            ["bluetooth scan", "bluetooth scan --seconds 20"],
            requires_root=True,
        ),
        Action(
            "bluetooth.device.pair",
            "Pair device",
            "Pair with a device by its MAC address (requires root).",
            _pair,
            [Param("mac", "Device address (AA:BB:CC:DD:EE:FF)")],
            ["bluetooth device pair AA:BB:CC:DD:EE:FF"],
            requires_root=True,
        ),
    ]
```

### `bluetooth/__init__.py` — registration

```python
"""Bluetooth module: discover and manage devices."""
from __future__ import annotations
from mac_and_seize.core.plugins import ModuleSpec
from mac_and_seize.modules.bluetooth.actions import (
    GROUP_DESCRIPTIONS, SERVICE, build_actions,
)
from mac_and_seize.modules.bluetooth.service import BluetoothService


def register() -> ModuleSpec:
    return ModuleSpec(
        name="bluetooth",
        services={SERVICE: BluetoothService},
        actions=build_actions(),
        group_descriptions=GROUP_DESCRIPTIONS,
        order=30,
    )
```

That's it. No edits anywhere else. Launch the app and try `bluetooth help`,
`bluetooth scan help`, `bluetooth device pair ...`.

---

## 11. Checklist

- [ ] New folder `mac_and_seize/modules/<name>/` with `__init__.py`.
- [ ] `register()` returns a `ModuleSpec`.
- [ ] Service key(s) are unique across modules and fetched via `context.service(key)`.
- [ ] Action `name`s are dotted paths; groups named consistently.
- [ ] `requires_root=True` on privileged actions (don't check root yourself).
- [ ] Handlers are thin and return plain data (`str`/`dict`/`list`); no printing.
- [ ] Bad input raises `ValueError`; operational failures raise `ModuleError`.
- [ ] `group_descriptions` added for each group (optional but recommended).
- [ ] Any new third-party dependency added to root `pyproject.toml`.
- [ ] No edits to `core/`, `cli/`, or other modules.

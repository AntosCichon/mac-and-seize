# mac_and_seize

Network interface and packet tooling: a Typer-based interactive CLI, with a
localhost web interface planned to sit alongside it on the same backend.

## Structure

```
mac_and_seize/
  __main__.py            entry point for `python -m mac_and_seize`
  cli/                    Typer app and interactive shell (front-end)
  core/                   framework-agnostic primitives: actions, context, plugin discovery
  modules/                feature modules (interface, capture, ...)
  config/                 configuration models and loader
  observability/          logging setup
  server/                 stub for the planned web interface
  util/                   internal helpers (system, export, static data)
```

### `cli/`

Typer application and the interactive shell that is the tool's primary
front-end.

| File | Purpose |
| --- | --- |
| `app.py` | Typer application and global callback: loads config, configures logging, builds the shared `AppContext`, registers the `serve` subcommand, and starts the interactive session when no subcommand is given. |
| `interactive.py` | The interactive shell: a navigable command tree built from modules' dotted action names, argument parsing, tab completion, help rendering, and generic result rendering. |
| `commands/serve.py` | The `serve` subcommand; delegates to `server.create_app`. |

### `core/`

Framework-agnostic primitives shared by every front-end. Nothing here imports
from `cli` or `server`.

| File | Purpose |
| --- | --- |
| `actions.py` | `Action` and `Param` — the declarative, front-end-agnostic description of a command: name, parameters, handler, examples, root requirement. |
| `plugins.py` | `discover_modules()` and `ModuleSpec` — imports every subpackage of `modules/` and collects each one's `register()` output. |
| `context.py` | `AppContext` — the application's shared state (config, timer, services, actions), built once at startup and threaded explicitly through the app. |
| `errors.py` | `ModuleError`, the base exception type modules raise for expected operational failures. |

### `modules/`

Self-contained, auto-discovered feature packages. See
[`modules/README.md`](modules/README.md) for the module authoring guide.

**`interface/`** — inspect and control network interfaces.

| File | Purpose |
| --- | --- |
| `net.py` | Low-level, privileged operations (`ip` subprocess calls, a raw `SIOCETHTOOL` ioctl for the factory MAC) and the `Interface` domain entity. |
| `service.py` | `InterfaceService` — validates and normalizes input, caches `Interface` instances, exposes the module's API. |
| `actions.py` | The `interface` command tree: `list`, `show`, `state.up/down`, `mac`, `ip4.add/remove/set`, `ip6.add/remove/set`. |

**`capture/`** — sniff and record packets.

| File | Purpose |
| --- | --- |
| `net.py` | `Packet`, a wrapper around scapy packets (ARP/ICMP/TCP/UDP factories, layer access, summaries), and `write_pcap()`. |
| `service.py` | `CaptureService` — `sniff()` and `send()` over scapy, plus `write_pcap()`. |
| `actions.py` | The top-level `capture` command. |

### `config/`

| File | Purpose |
| --- | --- |
| `settings.py` | Pydantic-settings models (`ServerConfig`, `LoggingConfig`, `SetupConfig`, `RuntimeConfig`, aggregated in `AppConfig`) and `load_config()`. |

### `observability/`

| File | Purpose |
| --- | --- |
| `setup.py` | `configure_logging()` and `get_logger()` — console and file handlers, plus an exit hook that archives the log directory. |
| `console.py` | `ColorFormatter`, an ANSI-colorizing `logging.Formatter`. |

### `server/`

| File | Purpose |
| --- | --- |
| `app.py` | `create_app(context)` — currently a stub that raises `ServerNotImplementedError`; see `server/README.md` for the intended design. |

### `util/`

| File | Purpose |
| --- | --- |
| `system.py` | `is_root()`, `relaunch_as_root()`. |
| `export.py` | `archive()` and `export_logs()` — zips log files into the export directory. |
| `static.py` | ANSI color codes, log-level colors, and the startup banner. |

## Wiring

The entry point (`main.py` at the repository root, or `python -m
mac_and_seize`) imports the Typer `app` from `cli/app.py`. Its callback loads
configuration (`config/settings.py`), configures logging
(`observability/setup.py`), and builds an `AppContext`
(`core/context.py`).

Building the context runs `discover_modules()` (`core/plugins.py`), which
imports every subpackage under `modules/` and calls its `register()`
function. Each module returns a `ModuleSpec` with a service factory and a
list of `Action`s; the context instantiates the services and merges the
actions into `context.actions`.

Unless a subcommand such as `serve` was given, control passes to
`run_interactive()` (`cli/interactive.py`), which builds a command tree from
the actions' dotted names and reads commands from the user. Dispatching a
command parses its arguments against the action's declared `Param`s, then
calls `action.run(context, values)`, which invokes the module's handler. A
handler fetches its module's service with `context.service(key)`, calls into
the module's `service.py`, which in turn drives the module's low-level
`net.py`. Handlers return plain `str` / `dict` / `list` data, which the shell
renders generically as a line, table, or numbered list.

Modules raise `ValueError` for invalid input and `core.errors.ModuleError`
(or a subclass) for operational failures; the shell catches both and prints a
clean message instead of a traceback. The planned web interface
(`server/`) is meant to be a second adapter over the same `context.actions` /
`context.service(key)` surface, so no business logic would need to move.

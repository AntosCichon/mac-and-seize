# mac_and_seize

Network interface and packet tooling: a Typer-based interactive CLI, with a
localhost web interface planned to sit alongside it on the same backend.

## Structure

```
mac_and_seize/
  __main__.py            entry point for `python -m mac_and_seize`
  cli/                    Typer app and interactive shell (front-end)
  core/                   framework-agnostic primitives: actions, context, presenter, plugin discovery
  modules/                feature modules (interface, capture, relay, ...)
  net/                    shared network domain: model (entities/value objects) + adapters (ip/scapy/ioctl) + session/relay bases
  config/                 configuration models and loader
  observability/          logging setup
  server/                 stub for the planned web interface
  util/                   internal helpers (system, export, formatting, static data)
```

Dependency direction: `cli`/`server` → `modules` → `net` → `core`. Feature
modules are independent plugins that never import one another; anything more than
one module needs (interfaces, packets, addresses, OS access) lives in `net/`.

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
| `context.py` | `AppContext` — the application's shared state (config, timer, services, actions, presenter), built once at startup and threaded explicitly through the app. |
| `errors.py` | `ModuleError`, the base exception type modules raise for expected operational failures. |
| `presenter.py` | `Presenter` port + `Column` + `NullPresenter` — how a front-end supplies interactive views (e.g. a scrollable table) and out-of-band status lines (`notify()`, for background work finishing) so modules render them without importing a front-end. |

### `modules/`

Self-contained, auto-discovered feature packages. See
[`modules/README.md`](modules/README.md) for the module authoring guide.

**`interface/`** — inspect and control network interfaces.

| File | Purpose |
| --- | --- |
| `service.py` | `InterfaceService` — parses input into `net` value objects, composes the `ip`/`ethtool`/`netifaces` adapters to build and mutate `Interface` entities, owns the registry and route-preservation workflow. |
| `actions.py` | The `interface` command tree: `list`, `show`, `state.up/down`, `mac`, `ip4.add/remove/set`, `ip6.add/remove/set`. |

**`capture/`** — sniff and record wired packets.

| File | Purpose |
| --- | --- |
| `service.py` | `CaptureService` — the wired capture service: include/exclude filters, socket-level interface selection, summary/inspect; builds on the shared `net.session.PacketSession` (packet store + `AsyncSniffer` lifecycle). |
| `filters.py` | Structured include/exclude capture filters and the per-packet matching engine. |
| `actions.py` | The `capture` command group (start/stop/export/import/clear/summary/inspect + `filter` subgroup). |

**`wireless/`** — 802.11 (Wi-Fi) monitor-mode capture; a peer of `capture/`, kept
separate because its operational model (monitor mode, channel hopping, PHY
lifecycle, driver/daemon coordination, and planned injection tooling) differs from
wired sniffing. Entering monitor mode exists only to enable capture, so it is done
quietly inside `capture start` and undone on `stop` (route-preservation style) —
there is no separate monitor/mode/channel command surface.

| File | Purpose |
| --- | --- |
| `capture.py` | `WirelessCaptureService` — monitor-mode frame capture on `net.session.PacketSession`; also owns the quiet monitor setup/teardown (switch a managed interface to monitor, or create a monitor VIF on a free PHY, and restore on stop), channel sweeping (background hopper), activity scan, and network/station views. |
| `filters.py` | Structured 802.11 include/exclude filters (bssid/ssid/type/subtype) and the matching engine. |
| `actions.py` | The `wireless` command group: `capture` (start/stop/inspect/networks/stations/summary/clear/export/import + `filter`) and `activity`. |

**`discovery/`** — find live hosts on the network (service/port discovery is a
stub for now).

| File | Purpose |
| --- | --- |
| `service.py` | `DiscoveryService` — session store of discovered `Host`s keyed by IP, background ARP sweep (pure scapy, no external `nmap`; one batch, local link only) of an address spec or a local interface's subnet, with an instant detach-cancel — a new scan can start at once while the abandoned probe drains (see `modules/README.md` §9). |
| `host.py` | `Host` record; hosts are found by the ARP sweep (inspired by nmap's `-PR`) or imported from a pcap, tracked in `Host.method` (`arp`/`pcap`). |
| `actions.py` | The `discovery` command group: `host` (scan/cancel/import/list/clear/summary) and a `service` stub. |

**`relay/`** — centralized traffic-relay/forwarding service. Turns the tool's
redirection primitives (`lan.arp`, `lan.dhcp server`, `lan.stp spoof`) into
real MiTMs. Flows are started implicitly by passing `--relay` (or `--nat-relay`
on `lan dhcp server`) to a redirection command; the module's own command surface
is view/stop only. See [`net/relay.py`](net/relay.py) and
[`net/adapters/forwarding.py`](net/adapters/forwarding.py) for the shared
plumbing this module orchestrates.

| File | Purpose |
| --- | --- |
| `service.py` | `RelayService` — session-scoped registry of running relay handles; owns `begin_l2_onseg` (ARP MiTM), `begin_l3_gateway_scapy` (rogue-DHCP one-way scapy bridge), `begin_l3_gateway_kernel` (rogue-DHCP two-way kernel NAT), `begin_straddle` (STP two-NIC bridge), plus `end`/`end_all`, NAT-set update hooks and a `subscribe_all` fan-out that `capture start --relay` attaches to. |
| `actions.py` | The `relay` command group: `list` (view running flows), `stop` (tear all down + restore any global state). |

### `net/`

Shared network domain layer (see [`net/README.md`](net/README.md) for the
model/adapters split and dependency rule).

| File | Purpose |
| --- | --- |
| `model/addresses.py` | `MacAddress`, `IPAddress`, `CIDR` — self-validating address value objects. |
| `model/route.py` | `Route` — a routing-table entry value object. |
| `model/interface.py` | `Interface` — the pure interface entity (data + `to_dict`, no I/O). |
| `model/packet.py` | `Packet` — the scapy packet wrapper (factories, layer access, summaries). |
| `session.py` | `PacketSession` — shared background packet-capture session base (packet store + `AsyncSniffer` lifecycle, pcap export/import), reused by the `capture` and `wireless` modules. |
| `relay.py` | `RelayFlow` + `RelaySession` — paired receive-and-reinject lifecycle used by the `relay` module: one or more `AsyncSniffer`s, per-flow `rewrite_fn` (dst-MAC only), self-echo suppression, subscriber fan-out for `capture start --relay`, and a monitor thread that fires an `on_death` callback on sniffer death / send-failure streak. Peer of `session.py`. |
| `adapters/ip.py` | Link/address/route operations via `ip`, plus sysfs `read_state`/`is_up`. |
| `adapters/ethtool.py` | `get_permanent_mac()` via a raw `SIOCETHTOOL` ioctl. |
| `adapters/netifaces_io.py` | Interface enumeration and address records via `netifaces`. |
| `adapters/scapy_io.py` | `send()`, `sniff()`, `write_pcap()`, `read_pcap()`, `available_interfaces()`, `refresh_interfaces()`, and host discovery (`expand_hosts()`, `arp_probe()`, `mac_vendor()`). |
| `adapters/wireless.py` | 802.11 control via nl80211/PyRIC: monitor mode, verified channel set, PHY topology (`list_phys`/`phy_of`/`interfaces_on_phy`), monitor-VIF create/teardown (`add_monitor`/`del_interface`), and `interfering_daemons()`. |
| `adapters/forwarding.py` | sysctl snapshot/restore (`SysctlSnapshot`, `snapshot_and_set`, `restore_sysctls`) and dedicated nftables tables (`mas_relay` INPUT-drop, `mas_relay_nat` MASQUERADE) used by the `relay` module; `purge_stale_tables()` self-heals across crashes. |
| `adapters/privileged.py` | `run()` (privileged-subprocess helper), `PrivilegedCommandError`, `family_flag()`. |

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
| `parse.py` | `split_values()` — expand one CLI token into a list/range of values (shared by the `capture` and `wireless` modules). |
| `export.py` | `archive()` and `export_logs()` — zips log files into the export directory. |
| `format.py` | `format_hms()` — render a duration in seconds as `HH:MM:SS`. |
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
the module's `service.py`, which in turn drives the shared `net/` layer (domain
model + OS/scapy adapters). Handlers return plain `str` / `dict` / `list` data,
which the shell renders generically as a line, table, or numbered list; an
interactive view (e.g. `capture inspect`) instead goes through
`context.presenter`.

Modules raise `ValueError` for invalid input and `core.errors.ModuleError`
(or a subclass) for operational failures; the shell catches both and prints a
clean message instead of a traceback. The planned web interface
(`server/`) is meant to be a second adapter over the same `context.actions` /
`context.service(key)` surface, so no business logic would need to move.

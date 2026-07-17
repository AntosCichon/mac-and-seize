"""Interactive session: a shell-like command REPL over the action registry.

Instead of a numbered menu, the user types commands with inline arguments,
shell style. Actions are organized into a tree from their dotted names
(``interface.ip4.add`` -> group ``interface`` -> group ``ip4`` -> command
``add``), with arbitrary nesting depth, and ``help`` works at every level:

    help                        # top-level: groups, commands, built-ins
    interface help              # commands within the 'interface' group
    interface ip4 help          # commands within the 'interface ip4' group
    interface ip4 add help      # arguments, usage, and examples for one command
    interface ip4 add eth0 192.168.1.50/24 --gateway 192.168.1.1

A ``cd``-style context makes long paths ergonomic: typing a *group* name
descends into it (the prompt then shows ``mac-and-seize/interface``) so its
commands run directly, and ``back`` moves one level up. Commands typed while in
a context resolve against that context first, then fall back to the tree root -
so top-level groups and commands (e.g. ``interface list``) stay reachable from
anywhere without leaving the current context.

This scales as the registry grows: adding an action to the registry makes it
appear in the right place with no changes here.
"""

from __future__ import annotations

import logging
import re
import shlex
import sys
from dataclasses import dataclass, field
from itertools import product
from typing import Callable

try:
    # Importing readline gives the built-in input() line editing and
    # up/down-arrow history. It must own the prompt (see _prompt) so it can
    # measure the prompt width and redraw the line correctly during history
    # navigation.
    import readline  # noqa: F401
except ImportError:  # pragma: no cover - readline is unavailable on some OSes
    readline = None

from rich.console import Console
from rich.table import Table

from mac_and_seize.cli.tui import PromptAwareLogHandler
from mac_and_seize.core.actions import Action
from mac_and_seize.core.context import AppContext
from mac_and_seize.core.errors import ModuleError
from mac_and_seize.observability import LOGGER_NAME, get_logger
from mac_and_seize.util.static import COLORS
from mac_and_seize.util.system import is_root, relaunch_as_root

console = Console()
logger = get_logger("mac_and_seize.cli.interactive")

_HELP_WORDS = {"help", "h", "?"}
_QUIT_WORDS = {"quit", "exit", "q"}
_BACK_WORDS = {"back", ".."}
# ``home`` jumps straight to the root context; ``/`` mirrors the ``/``-separated
# path shown in the prompt (mac-and-seize/interface -> root).
_HOME_WORDS = {"home", "/"}
# Built-ins offered as first-word completions (canonical spellings only).
_BUILTIN_WORDS = ["help", "back", "home", "sudo", "tasks", "quit"]


def _location(context_path: list[str]) -> str:
    """The prompt location: ``mac-and-seize`` plus the ``/``-joined context."""
    if context_path:
        return "mac-and-seize/" + "/".join(context_path)
    return "mac-and-seize"


def _prompt(context_path: list[str]) -> str:
    """Build the session prompt string for built-in ``input()``.

    Shows the current context as a ``/``-separated path (e.g.
    ``mac-and-seize/interface``). Red ``#`` when running as root, cyan ``>``
    otherwise. The prompt is passed straight to ``input()`` so readline owns it
    and can measure its width for correct redraws during history navigation.
    ANSI codes are therefore wrapped in readline's non-printing markers
    (``\\001``..``\\002``); without those, readline miscounts the width and
    up-arrow appears to eat the prompt. When not attached to an interactive TTY
    (or readline is missing) we return a plain, uncolored prompt so piped
    output stays clean.
    """
    color = "red" if is_root() else "cyan"
    char = "#" if is_root() else ">"
    location = _location(context_path)

    interactive = readline is not None and sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        return f"{location}{char} "

    def esc(*keys: str) -> str:
        return "\001" + "".join(COLORS[key] for key in keys) + "\002"

    return (
        f"{esc('bold', color)}{location}{esc('reset')}"
        f"{esc('dim')}{char}{esc('reset')} "
    )


class UsageError(Exception):
    """Raised when a command line cannot be parsed into an action's params."""


def _color(action: Action) -> str:
    """Actions that need root are shown in red, the rest in cyan."""
    return "red" if action.requires_root else "cyan"


@dataclass
class Node:
    """One node in the command tree.

    A node is either a *group* (has ``children`` and no ``action``) or a *leaf*
    command (has an ``action``). The tree is built from the actions' dotted
    names and supports arbitrary depth, e.g. ``interface.ip4.add``.
    """

    children: dict[str, "Node"] = field(default_factory=dict)
    action: Action | None = None

    @property
    def is_action(self) -> bool:
        return self.action is not None


@dataclass
class CommandTree:
    """Nested command tree built from the actions' dotted names.

    ``descriptions`` maps a dotted group path (e.g. ``"interface.ip4"``) to a
    human label shown in help; it is contributed by modules and merged on the
    :class:`AppContext`.
    """

    root: Node = field(default_factory=Node)
    descriptions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_actions(
        cls, actions: list[Action], descriptions: dict[str, str] | None = None
    ) -> "CommandTree":
        tree = cls(descriptions=dict(descriptions or {}))
        for action in actions:
            segments = action.name.split(".")
            node = tree.root
            for segment in segments[:-1]:
                node = node.children.setdefault(segment, Node())
            node.children.setdefault(segments[-1], Node()).action = action
        return tree


# --- Tab completion ---


class _Completer:
    """readline completer honoring the current context and top-level fallback.

    It reads the live line buffer, resolves the already-typed words the same way
    dispatch does (current context first, then the tree root), and offers the
    matching child names for the word under the cursor. Completion stops
    (returns nothing) once the cursor is past a command into its arguments.
    """

    def __init__(self, tree: CommandTree, get_context: Callable[[], list[str]]) -> None:
        self._tree = tree
        self._get_context = get_context
        self._matches: list[str] = []

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            self._matches = self._candidates(text)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def _candidates(self, text: str) -> list[str]:
        buffer = readline.get_line_buffer()
        prior = buffer[: readline.get_begidx()].split()
        context_path = self._get_context()
        local = set(_node_at(self._tree, context_path).children)
        top = set(self._tree.root.children)

        # First word: local commands/groups, top-level fallbacks, and built-ins.
        if not prior:
            names = local | top | set(_BUILTIN_WORDS)
            return sorted(n for n in names if n.startswith(text))

        first = prior[0].lower()
        if first in _HELP_WORDS:
            if len(prior) == 1:
                return sorted(n for n in local | top if n.startswith(text))
            return self._descend(context_path, prior[1], prior[1:], text)
        if (
            first in _BACK_WORDS
            or first in _HOME_WORDS
            or first in _QUIT_WORDS
            or first in ("sudo", "tasks")
        ):
            return []

        return self._descend(context_path, first, prior, text)

    def _descend(
        self, context_path: list[str], anchor: str, segments: list[str], text: str
    ) -> list[str]:
        """Complete children of the group reached by walking ``segments``.

        ``anchor`` (segments[0]) chooses the base via the same context-then-root
        rule dispatch uses; completion stops once a leaf command is reached.
        """
        base = _resolve_base(self._tree, context_path, anchor)
        if base is None:
            return []
        node = _walk_groups(base[0], segments)
        if node is None:
            return []
        return sorted(n for n in node.children if n.startswith(text))


def _walk_groups(node: Node, segments: list[str]) -> Node | None:
    """Follow ``segments`` through *group* nodes; ``None`` if any isn't a group."""
    for segment in segments:
        child = node.children.get(segment)
        if child is None or child.is_action:
            return None
        node = child
    return node


def _install_completion(completer: _Completer) -> None:
    """Bind tab completion, if readline is available (a no-op otherwise)."""
    if readline is None:
        return
    readline.set_completer(completer.complete)
    readline.set_completer_delims(" ")
    if readline.__doc__ and "libedit" in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")


# --- REPL loop ---


def run_interactive(context: AppContext) -> None:
    tree = CommandTree.from_actions(context.actions, context.group_descriptions)
    context_path: list[str] = []
    # The lambda reads the live `context_path`, so completions follow navigation.
    _install_completion(_Completer(tree, lambda: context_path))
    # Let a presenter (e.g. background scan completion) redraw the live prompt
    # when it prints out of band. The readline markers (\001/\002) are only for
    # input()'s width math, so strip them for a direct terminal write.
    if hasattr(context.presenter, "set_prompt_provider"):
        context.presenter.set_prompt_provider(
            lambda: _prompt(context_path).replace("\001", "").replace("\002", "")
        )
    # Route app log records around (not through) the live prompt for the
    # duration of the session: a scan worker logging while the user sits at the
    # prompt would otherwise corrupt the line (same failure mode as an
    # out-of-band notify()).
    _restore_log_handler = _install_prompt_log_handler(context)
    console.print(
        "\n[bold]Interactive session.[/] "
        "Type '[cyan]help[/]' to get started, '[cyan]quit[/]' to exit.\n"
    )
    logger.info("Interactive session started")

    try:
        while True:
            try:
                line = input(_prompt(context_path)).strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            if not line:
                continue
            try:
                tokens = shlex.split(line)
            except ValueError as exc:
                console.print(f"[red]Parse error:[/] {exc}")
                continue
            if not tokens:
                continue
            head = tokens[0].lower()
            if head in _QUIT_WORDS:
                break
            if head == "sudo":
                _relaunch_sudo()
                continue
            if head == "tasks":
                _show_tasks(context)
                continue
            if head in _BACK_WORDS:
                context_path = _go_back(context_path)
                continue
            if head in _HOME_WORDS:
                context_path = _go_home(context_path)
                continue

            try:
                context_path = _dispatch(context, tree, context_path, tokens)
            except UsageError as exc:
                console.print(f"[red]{exc}[/]")
            except Exception as exc:  # noqa: BLE001 - keep the session alive
                console.print(f"[red]Unexpected error:[/] {exc}")
                logger.exception("Unexpected error handling: %s", " ".join(tokens))
    finally:
        _restore_log_handler()

    console.print("Goodbye.")
    logger.info("Interactive session ended")


def _install_prompt_log_handler(context: AppContext) -> Callable[[], None]:
    """Swap the app's console log handler for a prompt-aware one for the session.

    Returns a zero-arg callable that restores the original handler. When the
    session isn't an interactive TTY, or the presenter can't redraw the prompt,
    this is a no-op (returns a callable that does nothing) so piped/headless
    runs keep the plain stderr handler.
    """
    interactive = (
        readline is not None
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and hasattr(context.presenter, "emit_line")
    )
    app_logger = logging.getLogger(LOGGER_NAME)
    original = next(
        (h for h in app_logger.handlers if h.get_name() == "console"), None
    )
    if not interactive or original is None:
        return lambda: None

    handler = PromptAwareLogHandler(context.presenter)
    handler.setLevel(original.level)
    handler.setFormatter(original.formatter)
    app_logger.removeHandler(original)
    app_logger.addHandler(handler)

    def restore() -> None:
        app_logger.removeHandler(handler)
        app_logger.addHandler(original)

    return restore


def _node_at(tree: CommandTree, path: list[str]) -> Node:
    """Return the node reached by walking ``path`` from the root (path is valid)."""
    node = tree.root
    for segment in path:
        node = node.children[segment]
    return node


def _resolve_base(
    tree: CommandTree, context_path: list[str], first_token: str
) -> tuple[Node, list[str]] | None:
    """Pick the node to resolve ``first_token`` against.

    Resolution prefers the *current context* so short commands work locally,
    then falls back to the tree *root* so top-level groups and commands stay
    reachable from anywhere (e.g. running ``interface list`` while in
    ``interface/state``). Returns ``(base_node, base_path)`` or ``None`` when the
    token is unknown in both places.
    """
    context_node = _node_at(tree, context_path)
    if first_token in context_node.children:
        return context_node, list(context_path)
    if first_token in tree.root.children:
        return tree.root, []
    return None


def _go_back(context_path: list[str]) -> list[str]:
    """Move one level up in the context, or warn when already at the top."""
    if not context_path:
        console.print("[yellow]Already at the top level.[/]")
        return context_path
    return context_path[:-1]


def _go_home(context_path: list[str]) -> list[str]:
    """Jump straight to the root context from any depth (``back`` to the top)."""
    if not context_path:
        console.print("[yellow]Already at the top level.[/]")
    return []


def _show_tasks(context: AppContext) -> None:
    """Built-in ``tasks``: list background tasks running across all modules."""
    running = context.tasks.running()
    if not running:
        console.print("No background tasks are running.")
        return
    _render([
        {
            "id": task.id,
            "started": task.started(),
            "runtime": task.runtime(),
            "command": task.command,
        }
        for task in running
    ])


def _relaunch_sudo() -> None:
    if is_root():
        console.print("[yellow]Already running as root.[/]")
        return
    console.print("Relaunching under sudo (enter your password if prompted)...")
    logger.info("Relaunching under sudo at user request")
    try:
        # On success this replaces the process and never returns.
        relaunch_as_root()
    except OSError as exc:
        console.print(f"[red]Failed to relaunch with sudo:[/] {exc}")


def _dispatch(
    context: AppContext,
    tree: CommandTree,
    context_path: list[str],
    tokens: list[str],
) -> list[str]:
    """Run a command, navigate into a group, or show help.

    Returns the (possibly updated) context path: typing a group name descends
    into it, running a command leaves the context unchanged.
    """
    if tokens[0].lower() in _HELP_WORDS:
        _help(tree, context_path, tokens[1:])
        return context_path

    base = _resolve_base(tree, context_path, tokens[0])
    if base is None:
        console.print(
            f"[yellow]Unknown command '{tokens[0]}'.[/] "
            "Type '[cyan]help[/]' to see options."
        )
        return context_path

    node, path = base
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.lower() in _HELP_WORDS:
            _node_help(tree.descriptions, node, path)
            return context_path
        child = node.children.get(token)
        if child is None:
            console.print(f"[yellow]Unknown command '{' '.join(path + [token])}'.[/]")
            _group_help(tree.descriptions, node, path)
            return context_path
        node = child
        path.append(token)
        index += 1
        if node.is_action:
            args = tokens[index:]
            if args and args[0].lower() in _HELP_WORDS:
                _command_help(node.action)
                return context_path
            _execute(context, node.action, args)
            return context_path

    # Consumed all tokens on a group node: enter that group's context.
    return path


# --- Argument parsing ---

# An inclusive integer range like ``1-3`` (used by ``multiple`` params).
_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")


def _convert(param, token: str):
    if param.type is int:
        try:
            return int(token)
        except ValueError as exc:
            raise UsageError(
                f"'{token}' is not a valid integer for '{param.name}'."
            ) from exc
    return token


def _parse_value(param, token: str):
    """Parse one CLI token for ``param``.

    Scalar params return a single converted value. ``multiple`` params return a
    *list*: the token is split on commas and each ``a-b`` chunk is expanded into
    the inclusive integer range ``a..b`` (ascending or descending). A lone value
    becomes a one-item list.
    """
    if not param.multiple:
        return _convert(param, token)

    items: list = []
    for chunk in token.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        match = _RANGE_RE.match(chunk)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            step = 1 if end >= start else -1
            items.extend(_convert(param, str(i)) for i in range(start, end + step, step))
        else:
            items.append(_convert(param, chunk))
    if not items:
        raise UsageError(f"'{param.name}' needs at least one value.")
    return items


def _parse_args(action: Action, tokens: list[str]) -> dict:
    required = [p for p in action.params if p.required]
    optional = {p.name: p for p in action.params if not p.required}

    positionals: list[str] = []
    values: dict = {}

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("--"):
            name = token[2:]
            if name not in optional:
                raise UsageError(
                    f"Unknown option '--{name}'.\nUsage: {_usage_line(action)}"
                )
            param = optional[name]
            if param.is_flag:
                values[name] = True
                index += 1
                continue
            index += 1
            if index >= len(tokens):
                raise UsageError(
                    f"Option '--{name}' needs a value.\nUsage: {_usage_line(action)}"
                )
            values[name] = _parse_value(param, tokens[index])
        else:
            positionals.append(token)
        index += 1

    if len(positionals) < len(required):
        missing = ", ".join(p.name for p in required[len(positionals):])
        raise UsageError(f"Missing argument(s): {missing}.\nUsage: {_usage_line(action)}")
    if len(positionals) > len(required):
        raise UsageError(f"Too many arguments.\nUsage: {_usage_line(action)}")

    for param, token in zip(required, positionals):
        values[param.name] = _parse_value(param, token)
    for name, param in optional.items():
        values.setdefault(name, param.default)
    return values


def _expand_combinations(action: Action, values: dict) -> list[dict]:
    """Fan ``values`` out over every ``multiple`` param into scalar-value dicts.

    Each ``multiple`` param holds a list; we take the cartesian product so the
    handler runs once per combination with a single value per param. Params with
    no values (an omitted optional) contribute a single ``None``. Without any
    ``multiple`` params this returns ``[values]`` unchanged.
    """
    multi = [p.name for p in action.params if p.multiple]
    if not multi:
        return [values]

    pools = []
    for name in multi:
        raw = values.get(name)
        pools.append(raw if isinstance(raw, list) and raw else [None])

    combinations = []
    for combo in product(*pools):
        scalar = dict(values)
        scalar.update(zip(multi, combo))
        combinations.append(scalar)
    return combinations


def _execute(context: AppContext, action: Action, tokens: list[str]) -> None:
    if action.requires_root and not is_root():
        console.print(
            f"[red]'{action.command_path}' requires root.[/] "
            "run [cyan]sudo[/] command to relaunch the app with root privileges."
        )
        logger.info("Blocked root-only action %s (not running as root)", action.name)
        return

    # Record the full invocation so handlers that spawn background tasks can
    # report exactly what was run (regardless of the current context).
    context.current_command = " ".join([action.command_path, *tokens]).strip()

    values = _parse_args(action, tokens)
    combinations = _expand_combinations(action, values)

    if len(combinations) == 1:
        try:
            result = action.run(context, combinations[0])
        except (ValueError, ModuleError, OSError) as exc:
            console.print(f"[red]Error:[/] {exc}")
            logger.warning("Action %s failed: %s", action.name, exc)
            return
        _render(result)
        return

    # Fan-out: run once per combination, reporting per-item errors but carrying
    # on, then render the aggregated results together.
    results: list = []
    for combo in combinations:
        try:
            result = action.run(context, combo)
        except (ValueError, ModuleError, OSError) as exc:
            console.print(f"[red]Error:[/] {exc}")
            logger.warning("Action %s failed: %s", action.name, exc)
            continue
        if result is None:
            continue
        if isinstance(result, list):
            results.extend(result)
        else:
            results.append(result)
    if results:
        _render(results)


# --- Help rendering (plain, wording-based; no menu table) ---


def _usage_line(action: Action) -> str:
    parts = [action.command_path]
    for param in action.params:
        if param.required:
            parts.append(f"<{param.name}{'...' if param.multiple else ''}>")
        elif param.is_flag:
            parts.append(f"[--{param.name}]")
        else:
            placeholder = f"<{param.name}{'...' if param.multiple else ''}>"
            parts.append(f"[--{param.name} {placeholder}]")
    return " ".join(parts)


def _help(tree: CommandTree, context_path: list[str], segments: list[str]) -> None:
    """Show help for ``segments`` (relative to context, then root), or, with no
    segments, for the current context."""
    if not segments or segments[0].lower() in _HELP_WORDS:
        _node_help(tree.descriptions, _node_at(tree, context_path), context_path)
        return

    base = _resolve_base(tree, context_path, segments[0])
    if base is None:
        console.print(f"[yellow]Unknown command '{segments[0]}'.[/] Type '[cyan]help[/]'.")
        return

    node, path = base
    for segment in segments:
        if segment.lower() in _HELP_WORDS:
            break
        child = node.children.get(segment)
        if child is None:
            console.print(f"[yellow]Unknown command '{' '.join(path + [segment])}'.[/]")
            _node_help(tree.descriptions, node, path)
            return
        node = child
        path.append(segment)
        if node.is_action:
            break
    _node_help(tree.descriptions, node, path)


def _node_help(descriptions: dict[str, str], node: Node, path: list[str]) -> None:
    """Show help for a node: a command's details, or a group's contents."""
    if node.is_action:
        _command_help(node.action)
    elif not path:
        _root_help(descriptions, node)
    else:
        _group_help(descriptions, node, path)


def _root_help(descriptions: dict[str, str], root: Node) -> None:
    groups = {n: c for n, c in root.children.items() if not c.is_action}
    commands = {n: c for n, c in root.children.items() if c.is_action}

    if groups:
        console.print("[bold]Command groups[/] (type a group name to enter it)")
        for name in groups:
            desc = descriptions.get(name, "commands")
            console.print(f"  [blue]{name + '/':<12}[/] {desc}")

    if commands:
        console.print("\n[bold]Commands[/]")
        for name, child in commands.items():
            console.print(f"  [{_color(child.action)}]{name:<12}[/] {child.action.title}")

    console.print("\n[bold]Built-in[/]")
    console.print(f"  [cyan]{'help, ?':<10}[/] Show help; 'help <command>' for details")
    console.print(f"  [cyan]{'back':<10}[/] Leave the current group (one level up)")
    console.print(f"  [cyan]{'home':<10}[/] Jump back to the top level from anywhere")
    console.print(f"  [cyan]{'sudo':<10}[/] Relaunch the app with root privileges")
    console.print(f"  [cyan]{'tasks':<10}[/] List running background tasks")
    console.print(f"  [cyan]{'quit':<10}[/] Leave the session (also: exit, Ctrl-D)")


def _group_help(descriptions: dict[str, str], node: Node, path: list[str]) -> None:
    label = " ".join(path)
    desc = descriptions.get(".".join(path), "")
    header = f"[bold]{label}[/] commands"
    console.print(f"{header} - {desc}" if desc else header)
    for name, child in node.children.items():
        if not child.is_action:
            sub_desc = descriptions.get(".".join(path + [name]), "commands")
            console.print(f"  [blue]{name + '/':<12}[/] {sub_desc}")
    for name, child in node.children.items():
        if child.is_action:
            console.print(f"  [{_color(child.action)}]{name:<12}[/] {child.action.title}")
    console.print(
        f"\nType '[cyan]{label} <command> help[/]' for arguments and examples."
    )


def _command_help(action: Action) -> None:
    root_tag = " [red](requires root)[/]" if action.requires_root else ""
    console.print(
        f"[bold {_color(action)}]{action.command_path}[/] - {action.title}{root_tag}"
    )
    console.print(action.description)
    console.print(f"\n[bold]Usage:[/] {_usage_line(action)}")

    if action.params:
        console.print("[bold]Arguments:[/]")
        for param in action.params:
            if param.is_flag:
                console.print(f"  [cyan]{f'--{param.name}':<14}[/] {param.help} [dim](flag)[/]")
                continue
            label = f"<{param.name}>" if param.required else f"--{param.name}"
            kind = "required" if param.required else "optional"
            note = ""
            if not param.required and param.default is not None:
                note = f", default: {param.default}"
            if param.multiple:
                note += ", accepts list a,b,c or range 1-3"
            console.print(
                f"  [cyan]{label:<14}[/] {param.help} "
                f"[dim]({kind}, {param.type.__name__}{note})[/]"
            )

    if action.examples:
        console.print("[bold]Examples:[/]")
        for example in action.examples:
            console.print(f"  [green]{example}[/]")


# --- Result rendering ---


def _render(result) -> None:
    if result is None:
        return
    if isinstance(result, str):
        console.print(f"[green]{result}[/]")
        return
    if isinstance(result, dict):
        table = Table(show_header=False)
        table.add_column("field", style="cyan")
        table.add_column("value")
        for key, value in result.items():
            table.add_row(str(key), str(value))
        console.print(table)
        return
    if isinstance(result, list):
        if result and all(isinstance(item, dict) for item in result):
            columns = list(result[0].keys())
            table = Table()
            for column in columns:
                table.add_column(column, style="cyan" if column == "name" else None)
            for row in result:
                table.add_row(*[str(row.get(column, "")) for column in columns])
            console.print(table)
        else:
            for index, item in enumerate(result, start=1):
                console.print(f"{index:>4}  {item}")
        return
    console.print(str(result))

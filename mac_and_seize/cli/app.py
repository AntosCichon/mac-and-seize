"""Typer application: the entry point and its global callback.

Philosophy: the app is *interactive-first*. Running it with no subcommand
loads config, sets up logging, builds the shared :class:`AppContext`, and drops
the user into an interactive session of predefined actions (mirroring how the
web interface will present those same actions). The only explicit subcommand is
``serve`` (the future web interface).
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from pydantic import ValidationError

from mac_and_seize.cli.commands.serve import serve
from mac_and_seize.cli.interactive import run_interactive
from mac_and_seize.cli.tui import CursesPresenter
from mac_and_seize.config import load_config
from mac_and_seize.core.context import AppContext
from mac_and_seize.observability import configure_logging, get_logger
from mac_and_seize.util.static import COLORS, WELCOME_ART

app = typer.Typer(
    name="mac-and-seize",
    help="Network interface and packet tooling (interactive).",
    add_completion=False,
)

app.command("serve", help="Start the localhost web interface (not implemented).")(serve)


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    config: Path = typer.Option(
        Path("config.toml"),
        "-c",
        "--config",
        help="Path to the configuration file.",
        metavar="PATH",
    ),
    log_level: Optional[LogLevel] = typer.Option(
        None,
        "-l",
        "--log-level",
        help="Override the configured logging level.",
    ),
) -> None:
    """Set up the app, then start the interactive session (unless a subcommand
    like ``serve`` was given).

    Root is *not* required to launch the app; individual actions that need it
    are gated at execution time (see the interactive session).
    """
    overrides: dict = {}
    if log_level is not None:
        overrides["logging"] = {"level": log_level.value}

    try:
        cfg = load_config(config, **overrides)
    except ValidationError as exc:
        typer.secho(f"Invalid configuration ({config}):", fg=typer.colors.RED, err=True)
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    configure_logging(cfg)
    ctx.obj = AppContext.create(cfg)
    ctx.obj.presenter = CursesPresenter()

    if sys.stderr.isatty():
        typer.echo(f"{COLORS['yellow']}{WELCOME_ART}{COLORS['reset']}", err=True)

    get_logger("mac_and_seize.cli").info("Application started")

    if ctx.invoked_subcommand is None:
        run_interactive(ctx.obj)

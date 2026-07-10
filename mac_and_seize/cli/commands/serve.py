"""``serve`` command: boot the localhost web interface (stub for now)."""

from __future__ import annotations

import typer

from mac_and_seize.core.context import AppContext
from mac_and_seize.observability import get_logger
from mac_and_seize.server import ServerNotImplementedError, create_app


def serve(ctx: typer.Context) -> None:
    """Start the web interface (not yet implemented)."""
    context: AppContext = ctx.obj
    logger = get_logger("mac_and_seize.cli.serve")

    host = str(context.config.server.listen_address)
    port = context.config.server.port
    logger.info("serve requested for http://%s:%s", host, port)

    try:
        create_app(context)
    except ServerNotImplementedError as exc:
        typer.secho(str(exc), fg=typer.colors.YELLOW, err=True)
        logger.warning("Web interface not implemented; nothing to serve.")
        raise typer.Exit(code=1) from exc

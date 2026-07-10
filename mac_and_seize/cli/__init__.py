"""Typer command-line interface.

A thin adapter layer: commands parse arguments and delegate to the services in
``mac_and_seize.core.services``. No business logic lives here.
"""

from mac_and_seize.cli.app import app

__all__ = ["app"]

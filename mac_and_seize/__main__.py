"""Entry point for ``python -m mac_and_seize``.

Kept intentionally thin: all wiring lives in the Typer app.
"""

from mac_and_seize.cli.app import app

if __name__ == "__main__":
    app()

"""mac-and-seize: network interface and packet tooling.

The package is organized in layers:

- ``config``        - Pydantic-settings configuration models and loader.
- ``observability`` - stdlib logging setup (console + file + zip-on-exit).
- ``core``          - framework-agnostic domain (``net``) and the service
                      layer (``services``) that is the single API surface
                      shared by the CLI and the (future) web interface.
- ``cli``           - Typer command-line interface (a thin adapter).
- ``server``        - documented stub for the planned localhost web UI.
- ``util``          - small internal helpers (system, export, static data).
"""

__version__ = "0.1.0"

#!/usr/bin/env python3
"""Standalone entry point for mac-and-seize.

No installation required - clone the repo and run this file. The same entry
point serves both the web service and the individual commands:

    python main.py --help              # list available commands
    python main.py serve               # start the localhost web service
    python main.py interface list      # run a command directly
    python main.py capture eth0 -n 10  # ...

Or via uv, which manages the virtual environment for you:

    uv run main.py serve
"""

from mac_and_seize.cli.app import app

if __name__ == "__main__":
    app()

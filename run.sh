#!/usr/bin/env bash
#
# Standalone launcher for mac-and-seize. Clone the repo and run this script.
#
# Examples:
#   ./run.sh serve                 # start the localhost web service
#   ./run.sh interface list        # run a command
#   ./run.sh capture eth0 -n 10    # ...
#   ./run.sh --help                # list commands
#
# Prefers `uv` (which auto-creates/syncs the virtual environment on first run).
# Falls back to the local .venv, then to system python3.

set -euo pipefail
cd "$(dirname "$0")"

if command -v uv >/dev/null 2>&1; then
    exec uv run python main.py "$@"
elif [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python main.py "$@"
else
    exec python3 main.py "$@"
fi

"""Localhost web interface (planned).

This package is intentionally a documented stub. The architecture is arranged
so the web layer, once implemented, depends only on the service layer in
``mac_and_seize.core.services`` - the exact same API the CLI uses - so no
business logic needs to be duplicated or moved.

See ``mac_and_seize/server/README.md`` for the intended design.
"""

from mac_and_seize.server.app import ServerNotImplementedError, create_app

__all__ = ["ServerNotImplementedError", "create_app"]

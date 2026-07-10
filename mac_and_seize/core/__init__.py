"""Framework-agnostic core: domain (``net``) and the service layer.

Nothing in ``core`` may import from ``cli`` or ``server`` - the dependency
arrow points inward. Both the CLI and the future web interface depend on the
services exposed here.
"""

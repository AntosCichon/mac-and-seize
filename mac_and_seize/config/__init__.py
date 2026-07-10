"""Application configuration.

Exposes the strongly-typed :class:`AppConfig` model and the :func:`load_config`
factory. Configuration is layered (highest priority first):

    explicit overrides  >  environment (``MAS_*``)  >  TOML file  >  defaults
"""

from mac_and_seize.config.settings import (
    AppConfig,
    LoggingConfig,
    RuntimeConfig,
    ServerConfig,
    SetupConfig,
    load_config,
)

__all__ = [
    "AppConfig",
    "LoggingConfig",
    "RuntimeConfig",
    "ServerConfig",
    "SetupConfig",
    "load_config",
]

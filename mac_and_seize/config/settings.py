"""Pydantic-settings configuration models and loader.

Design notes
------------
- Models are *strict* (``extra="forbid"``) so typos in the TOML file or in
  environment variables fail loudly instead of being silently ignored (the
  previous implementation prompted for input at runtime, which is unsafe for
  a long-running / web context).
- The TOML file path is dynamic (chosen via the ``--config`` CLI option), so
  it is injected through ``settings_customise_sources`` rather than the static
  ``toml_file`` config key.
"""

from __future__ import annotations

import shutil
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

_STRICT = ConfigDict(extra="forbid")


class ServerConfig(BaseModel):
    model_config = _STRICT

    port: Annotated[int, Field(ge=0, le=65535)] = 8080
    listen_address: IPv4Address = IPv4Address("127.0.0.1")


class LoggingConfig(BaseModel):
    model_config = _STRICT

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    directory: Path = Path("logs")
    filename: str = Field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d_%H-%M-%S.log")
    )
    remove_on_exit: bool = True


class SetupConfig(BaseModel):
    model_config = _STRICT

    export_directory: Path = Path("exports")
    timezone_offset: Annotated[int, Field(ge=-12, le=14)] = 0
    first_execute: bool = False


def _default_terminal_width() -> int:
    return shutil.get_terminal_size(fallback=(80, 24)).columns


class RuntimeConfig(BaseModel):
    model_config = _STRICT

    root_directory: Path = Field(default_factory=Path.cwd)
    terminal_width: int = Field(default_factory=_default_terminal_width)


# Set by ``load_config`` so ``settings_customise_sources`` (a classmethod that
# cannot see instance arguments) knows which TOML file to read.
_toml_path: Path | None = None


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MAS_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    setup: SetupConfig = Field(default_factory=SetupConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: list[PydanticBaseSettingsSource] = [
            init_settings,
            env_settings,
            dotenv_settings,
        ]
        if _toml_path is not None:
            sources.append(TomlConfigSettingsSource(settings_cls, toml_file=_toml_path))
        return tuple(sources)

    def dump(self) -> str:
        return self.model_dump_json(indent=4)


def load_config(config_path: str | Path = "config.toml", **overrides) -> AppConfig:
    """Build an :class:`AppConfig`.

    ``overrides`` (e.g. ``logging={"level": "DEBUG"}`` from a CLI flag) take
    precedence over environment variables and the TOML file. A missing TOML
    file is not an error - defaults are used.
    """
    global _toml_path
    _toml_path = Path(config_path)
    return AppConfig(**overrides)

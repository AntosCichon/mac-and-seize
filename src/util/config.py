from datetime import datetime
from pydantic import BaseModel, Field, DirectoryPath
from pathlib import Path
from ipaddress import IPv4Address
from argparse import Namespace
from typing import Annotated, Literal

class ServerConfig(BaseModel):
    port: Annotated[int, Field(ge=0, le=65535)] = 8080
    listen_address: IPv4Address = IPv4Address("127.0.0.1")

class LogConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    directory: DirectoryPath = Path("./logs")
    filename: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d_%H-%M.log"))

class SetupConfig(BaseModel):
    config_path: Path = Path("config.toml")

class AppConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    log: LogConfig = LogConfig()
    setup: SetupConfig = SetupConfig()

_config: AppConfig | None = None

def load_config(args: Namespace) -> bool:
    global _config
    raw: dict = {}
    _config = AppConfig.model_validate(raw)
    return _config is not None

def get_config() -> AppConfig:
    if _config is None:
        raise ValueError("Config not loaded")
    return _config
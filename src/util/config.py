from datetime import datetime, timedelta, timezone
import os
from pydantic import BaseModel, Field, ConfigDict
from pathlib import Path
from ipaddress import IPv4Address
from argparse import Namespace
from typing import Annotated, Literal
import tomllib
from src.util.cli import get_cli_args

class CustomBaseModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    def __getattr__(self, name):
        if not (name.startswith("__") and name.endswith("__")):
            from src.util.logging import TerminalMessage, LogMessage
            LogMessage(f"Attempted to access non-existent config setting \"{name}\". Asking user for input.", level = "WARNING")
            TerminalMessage(f"Setting \"{name}\" does not exist. Please enter a value:", end = " ")
            new_value = input()
            super().__setattr__(name, new_value)
            return new_value

    def __setattr__(self, name, value):
        if not name.startswith("_"):
            old_value = self.__dict__.get(name)
            if old_value != value:
                from src.util.logging import LogMessage
                LogMessage(f"Setting \"{name}\" has been modified: {old_value} -> {value}", level="WARNING")
        super().__setattr__(name, value)

class ServerConfig(CustomBaseModel):
    port: Annotated[int, Field(ge=0, le=65535)] = 8080
    listen_address: IPv4Address = IPv4Address("127.0.0.1")

class LoggingConfig(CustomBaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    directory: Path = Path("logs")
    filename: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d_%H:%M.log"))

class SetupConfig(CustomBaseModel):
    config_path: Path = Path("config.toml")
    timezone_offset: Annotated[int, Field(ge=-12, le=14)] = 0

class RuntimeConfig(CustomBaseModel):
    root_directory: Path = Path(os.getcwd())
    terminal_width: int = os.get_terminal_size().columns

class AppConfig(BaseModel):

    server: ServerConfig = ServerConfig()
    logging: LoggingConfig = LoggingConfig()
    setup: SetupConfig = SetupConfig()
    runtime: RuntimeConfig = RuntimeConfig()

    def dump(self):
        return self.model_dump_json(indent = 4)

    def __getattr__(self, name):
        if not name.startswith("_"):
            try:
                return super().__getattribute__(name)
            except AttributeError:
                from src.util.logging import LogMessage, TerminalMessage
                LogMessage(f"Attempted to access non-existent config section \"{name}\", exiting.", level = "ERROR")
                TerminalMessage(f"Config section \"{name}\" does not exist, check your config file.", color = "red")
                exit(1)
        return super().__getattribute__(name)

class Timer:
    def __init__(self):
        self.timezone = timezone(timedelta(hours = get_config().setup.timezone_offset))
        self.start_time = datetime.now(self.timezone)
        self.stamp = lambda: datetime.now(self.timezone)
        self._measure = []

    def runtime(self, format: str = "seconds", reference = None) -> str:
        delta = (self.stamp() - (self.start_time if reference is None else self._measure[reference])).total_seconds()
        if format == "seconds":
            return "%.2f" % delta
        if format == "time":
            s = int(delta)
            return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"
        else:
            return str(delta)
        
    def measure_start(self) -> int:
        self._measure.append(datetime.now(self.timezone))
        return len(self._measure) - 1


_config: AppConfig | None = None
_timer: "Timer | None" = None

def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = load_config(get_cli_args())
    return _config

def get_timer() -> "Timer":
    global _timer
    if _timer is None:
        _timer = Timer()
    return _timer

def load_config(cli_args: Namespace) -> AppConfig:
    config_path = Path(cli_args.setup__config_path)
    with open(config_path, "rb") as f:
        raw: dict = tomllib.load(f)

    for key, value in vars(cli_args).items():
        section, setting = key.split("__", 1)
        if section in raw:
            raw[section][setting] = value
        else:
            raw[section] = {setting: value}

    return AppConfig.model_validate(raw)
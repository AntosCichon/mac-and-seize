from inspect import stack
from src.util.static import LEVELS, COLORS
from src.util.config import get_timer, get_config

config = get_config()
timer = get_timer()

# Set up logging directory
config.logging.directory.mkdir(parents = True, exist_ok = True)
(config.logging.directory / config.logging.filename).touch(exist_ok = True)

class Message():
    def __init__(self, content):
        self.timestamp = timer.stamp()
        self.runtime = timer.runtime()
        self.content = content
        self.origin = stack()[2]

class LogMessage(Message):
    def __init__(self, content, level = "INFO", silent = False):
        super().__init__(content)
        self.level = level
        if not silent and LEVELS.index(level) >= LEVELS.index(config.logging.level):
            self.write()

    def format(self):
        return f"[{self.timestamp}] [{self.runtime}] [{self.level}] [{self.origin.filename}:{self.origin.lineno}] [\n{self.content}\n]"
    
    def write(self):
        log_file = config.logging.directory / config.logging.filename
        with open(log_file, "a") as f:
            f.write(self.format() + "\n")

class TerminalMessage(Message):
    def __init__(self, content, silent = False, include_stamp = True, padding_char = None, begin = "", end = "\n", color = None):
        super().__init__(content)
        if not silent:
            print(self.format(padding_char, include_stamp, begin, end, color), end="")
    
    def format(self, padding_char, include_stamp, begin, end, color):
        color = COLORS.get(color, "") if color else ""
        stamp = f"({self.runtime}s) " if include_stamp else ""
        reset = COLORS["reset"] if color else ""
        text = f"{color}{begin}{stamp}{self.content}"
        padded = f"{text}{padding_char * (config.runtime.terminal_width - len(text) - 1) if padding_char else ''}"
        return f"{padded}{end}{reset}"

import os
import time
os.chdir(os.path.dirname(__file__))

from src.util.config import get_config, get_timer
from src.util.logging import LogMessage, TerminalMessage
from src.util.export import export_logs
from src.util.static import WELCOME_ART
from src.net.interface import Interface

def main():
    i = Interface("eth1")
    i.up()
    print("Interface state:", i.get_state())
    time.sleep(5)
    print("Bringing interface down...")
    i.down()
    print("Interface state:", i.get_state())
    time.sleep(5)
    i.up()

if __name__ == "__main__":
    global config, timer
    config = get_config()
    timer = get_timer()
    TerminalMessage(WELCOME_ART, include_stamp = False, color = "yellow")
    LogMessage(f"Application started, configuration loaded:\n{config.dump()}")
    main()
    export_logs(remove_original = config.logging.remove_on_exit)
    exit(0)
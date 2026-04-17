import os
os.chdir(os.path.dirname(__file__))

from src.util.config import get_config, get_timer
from src.util.setup import run_setup

def main():
    print("MAC & SEIZE entry point")

if __name__ == "__main__":
    if not run_setup():
        print("Setup failed, exiting.")
        exit(1)
    global config, timer
    config = get_config()
    timer = get_timer()
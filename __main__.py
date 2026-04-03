import os
os.chdir(os.path.dirname(__file__))

from src.util.config import get_config, get_timer

def main():
    print("MAC & SEIZE entry point")

if __name__ == "__main__":
    global config, timer
    config = get_config()
    timer = get_timer()
    main()
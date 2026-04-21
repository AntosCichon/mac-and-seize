import sys
import os

def require_root():
    if os.geteuid() != 0:
        print("This tool requires root privileges. Enter password to continue or press Ctrl+C to exit.")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
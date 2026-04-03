class Message():
    def __init__(self, content):
        pass

class LogMessage(Message):
    def __init__(self, content, level = None, silent = False):
        pass
class TerminalMessage(Message):
    def __init__(self, content, silent = False, include_stamp = True, padding_char = None, begin = "", end = "\n", color = None):
        pass
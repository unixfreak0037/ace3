import logging

class MockLogger:
    def __init__(self, level=logging.WARNING):
        self.output = ''
        self.level = level

    def log(self, level, message):
        if level < self.level:
            return
        level_name = logging._levelToName[level]
        self.output += f'[{level_name}] {message}\n'

    def debug(self, message):
        self.log(logging.DEBUG, message)

    def info(self, message):
        self.log(logging.INFO, message)

    def warning(self, message):
        self.log(logging.WARNING, message)

    def error(self, message):
        self.log(logging.ERROR, message)

    def critical(self, message):
        self.log(logging.CRITICAL, message)

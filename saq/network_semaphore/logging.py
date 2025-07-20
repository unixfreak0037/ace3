import logging
from threading import RLock, Semaphore


class LoggingSemaphore(Semaphore):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.count = 0
        self.count_lock = RLock()
        self.semaphore_name = None

    def acquire(self, *args, **kwargs):
        result = super().acquire(*args, **kwargs)
        if result:
            with self.count_lock:
                self.count += 1
            logging.debug(f"acquire: semaphore {self.semaphore_name} count is {self.count}")

        return result

    def release(self, *args, **kwargs):
        super(LoggingSemaphore, self).release(*args, **kwargs)
        with self.count_lock:
            self.count -= 1
        logging.debug(f"release: semaphore {self.semaphore_name} count is {self.count}")



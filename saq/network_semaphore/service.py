from saq.network_semaphore.server import NetworkSemaphoreServer
from saq.service import ACEServiceInterface


class NetworkSemaphoreService(ACEServiceInterface):
    def __init__(self):
        self.server = NetworkSemaphoreServer()

    def start(self):
        self.server.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        self.server.wait_for_start()

    def start_single_threaded(self):
        raise NotImplementedError("NetworkSemaphoreService does not support single threaded mode")

    def stop(self):
        self.server.stop()

    def wait(self):
        self.server.wait()
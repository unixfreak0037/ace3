from saq.network_semaphore.client import NetworkSemaphoreClient
from saq.network_semaphore.interfaces import SemaphoreInterface


class SemaphoreAdapter:
    """Adapter that wraps a NetworkSemaphoreClient to implement SemaphoreInterface."""

    def __init__(self, semaphore_client):
        self._semaphore = semaphore_client

    def acquire(self, name: str) -> bool:
        return self._semaphore.acquire(name)

    def release(self):
        return self._semaphore.release()

    def cancel_request(self):
        return self._semaphore.cancel_request()


def create_semaphore() -> SemaphoreInterface:
    """Create a new semaphore instance."""
    client = NetworkSemaphoreClient()
    return SemaphoreAdapter(client)
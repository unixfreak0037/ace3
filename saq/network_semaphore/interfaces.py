from typing import Protocol


class SemaphoreInterface(Protocol):
    """Interface for semaphore operations."""

    def acquire(self, name: str) -> bool:
        """Acquire semaphore with given name."""
        ...

    def release(self):
        """Release the semaphore."""
        ...

    def cancel_request(self):
        """Cancel semaphore request."""
        ...
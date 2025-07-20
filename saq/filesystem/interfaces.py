from typing import Protocol


class FileSystemInterface(Protocol):
    """Interface for file system operations."""

    def exists(self, path: str) -> bool:
        """Check if path exists."""
        ...

    def get_mtime(self, path: str) -> float:
        """Get modification time."""
        ...

    def create_directory(self, path: str):
        """Create directory."""
        ...
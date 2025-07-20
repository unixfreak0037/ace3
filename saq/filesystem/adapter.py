import os


class FileSystemAdapter:
    """Adapter that implements FileSystemInterface using the standard library."""

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def get_mtime(self, path: str) -> float:
        return os.stat(path).st_mtime

    def create_directory(self, path: str):
        os.makedirs(path, exist_ok=True)
from saq.analysis.file_manager.file_manager_adapter import FileManagerAdapter
from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
from saq.analysis.file_manager.local_file_manager import LocalFileManager


def create_file_manager(storage_dir: str) -> FileManagerInterface:
    return FileManagerAdapter(LocalFileManager(storage_dir))
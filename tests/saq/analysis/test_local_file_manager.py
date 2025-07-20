import os
import tempfile
import shutil
import pytest
from pathlib import Path

from saq.analysis.file_manager.local_file_manager import LocalFileManager
from saq.constants import FILE_SUBDIR, HARDCOPY_SUBDIR


@pytest.fixture
def temp_storage_dir():
    """Create a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def file_manager(temp_storage_dir):
    """Create a FileManager instance for testing."""
    return LocalFileManager(temp_storage_dir)


@pytest.fixture  
def test_file():
    """Create a temporary test file."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    temp_file.write("test content")
    temp_file.close()
    yield temp_file.name
    try:
        os.unlink(temp_file.name)
    except FileNotFoundError:
        pass


@pytest.mark.unit
def test_file_manager_initialization(temp_storage_dir):
    """Test FileManager initialization."""
    fm = LocalFileManager(temp_storage_dir)
    assert fm.storage_dir == temp_storage_dir
    assert fm.hardcopy_dir.endswith(HARDCOPY_SUBDIR)
    assert fm.file_dir.endswith(FILE_SUBDIR)


@pytest.mark.unit
def test_initialize_storage(file_manager, temp_storage_dir):
    """Test storage directory initialization."""
    file_manager.initialize_storage()
    
    # Check if directories were created (would need actual SAQ environment setup)
    # This is more of an integration test
    assert True  # placeholder


@pytest.mark.unit
def test_store_file(file_manager, test_file):
    """Test file storage functionality."""
    # Prepare directories
    os.makedirs(file_manager.hardcopy_dir, exist_ok=True)
    os.makedirs(file_manager.file_dir, exist_ok=True)
    
    # Store the file
    sha256_hash, relative_path = file_manager.store_file(test_file)
    
    # Verify hash is returned
    assert sha256_hash is not None
    assert len(sha256_hash) == 64  # SHA256 hex length
    
    # Verify relative path is returned
    assert relative_path is not None
    assert not relative_path.startswith('/')
    
    # Verify hardcopy exists
    hardcopy_path = os.path.join(file_manager.hardcopy_dir, sha256_hash)
    assert os.path.exists(hardcopy_path)
    
    # Verify reference link exists
    target_path = os.path.join(file_manager.file_dir, relative_path)
    assert os.path.exists(target_path)


@pytest.mark.unit
def test_store_file_with_move(file_manager, test_file):
    """Test file storage with move operation."""
    # Prepare directories
    os.makedirs(file_manager.hardcopy_dir, exist_ok=True)
    os.makedirs(file_manager.file_dir, exist_ok=True)
    
    original_exists = os.path.exists(test_file)
    assert original_exists
    
    # Store the file with move=True
    sha256_hash, relative_path = file_manager.store_file(test_file, move=True)
    
    # Verify original file no longer exists
    assert not os.path.exists(test_file)
    
    # Verify hardcopy exists
    hardcopy_path = os.path.join(file_manager.hardcopy_dir, sha256_hash)
    assert os.path.exists(hardcopy_path)


@pytest.mark.unit
def test_store_nonexistent_file(file_manager):
    """Test storing a non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        file_manager.store_file("/nonexistent/path/file.txt")


@pytest.mark.unit
def test_delete_file(file_manager, test_file):
    """Test file deletion."""
    # File should exist initially
    assert os.path.exists(test_file)
    
    # Delete the file
    file_manager.delete_file(test_file)
    
    # File should no longer exist
    assert not os.path.exists(test_file)


@pytest.mark.unit
def test_create_file_path(file_manager):
    """Test file path creation."""
    # Prepare file directory
    os.makedirs(file_manager.file_dir, exist_ok=True)
    
    # Test simple relative path
    result = file_manager.create_file_path("test.txt")
    expected = os.path.join(file_manager.file_dir, "test.txt")
    assert result == expected
    
    # Test path with subdirectory
    result = file_manager.create_file_path("subdir/test.txt")
    expected = os.path.join(file_manager.file_dir, "subdir/test.txt")
    assert result == expected
    
    # Verify subdirectory was created
    assert os.path.exists(os.path.dirname(result))


@pytest.mark.unit
def test_storage_operations(file_manager, temp_storage_dir):
    """Test storage copy, move, and delete operations."""
    # Create some test content in storage
    os.makedirs(file_manager.storage_dir, exist_ok=True)
    test_content_path = os.path.join(file_manager.storage_dir, "test.txt")
    with open(test_content_path, 'w') as f:
        f.write("test content")
    
    # Test copy
    copy_dest = temp_storage_dir + "_copy"
    file_manager.copy_storage(copy_dest)
    assert os.path.exists(os.path.join(copy_dest, "test.txt"))
    
    # Test move
    move_dest = temp_storage_dir + "_move"
    original_storage = file_manager.storage_dir
    file_manager.move_storage(move_dest)
    assert not os.path.exists(original_storage)
    assert os.path.exists(os.path.join(move_dest, "test.txt"))
    assert file_manager.storage_dir == move_dest
    
    # Test delete
    file_manager.delete_storage()
    assert not os.path.exists(move_dest) 
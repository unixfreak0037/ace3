import time
import uuid

import pytest

from saq.engine.lock_manager.distributed import DistributedLockManager
from saq.database.util.locking import force_release_lock


@pytest.mark.unit
class TestDistributedLockManager:
    
    def test_init(self):
        """Test that DistributedLockManager initializes correctly."""
        manager = DistributedLockManager()
        assert manager.lock_uuid is not None
        assert manager.lock_owner is not None
        assert not manager.is_keepalive_active
        assert manager.current_lock_target is None
        
    def test_init_with_params(self):
        """Test initialization with specific parameters."""
        lock_uuid = str(uuid.uuid4())
        lock_owner = "test-owner"
        
        manager = DistributedLockManager(lock_uuid=lock_uuid, lock_owner=lock_owner)
        assert manager.lock_uuid == lock_uuid
        assert manager.lock_owner == lock_owner
        
    def test_acquire_and_release_lock(self):
        """Test basic lock acquisition and release."""
        manager = DistributedLockManager(lock_owner="test-acquire-release")
        target_uuid = str(uuid.uuid4())
        
        # Should be able to acquire a new lock
        assert manager.acquire_lock(target_uuid)
        
        # Should be able to release the lock
        assert manager.release_lock(target_uuid)
        
    def test_lock_conflict(self):
        """Test that two managers cannot acquire the same lock."""
        manager1 = DistributedLockManager(lock_owner="test-manager-1")
        manager2 = DistributedLockManager(lock_owner="test-manager-2")
        target_uuid = str(uuid.uuid4())
        
        try:
            # First manager acquires lock
            assert manager1.acquire_lock(target_uuid)
            
            # Second manager should not be able to acquire the same lock
            assert not manager2.acquire_lock(target_uuid)
            
        finally:
            # Clean up
            manager1.release_lock(target_uuid)
            
    def test_start_stop_keepalive(self):
        """Test the keepalive functionality."""
        manager = DistributedLockManager(lock_owner="test-keepalive")
        target_uuid = str(uuid.uuid4())
        
        try:
            # Should be able to start keepalive
            assert manager.start_keepalive(target_uuid)
            assert manager.is_keepalive_active
            assert manager.current_lock_target == target_uuid
            
            # Give it a moment to start
            time.sleep(0.1)
            
            # Stop keepalive
            manager.stop_keepalive()
            assert not manager.is_keepalive_active
            assert manager.current_lock_target is None
            
        finally:
            # Ensure cleanup
            force_release_lock(target_uuid)
            
    def test_keepalive_prevents_duplicate(self):
        """Test that starting keepalive on a different target while one is active fails."""
        manager = DistributedLockManager(lock_owner="test-duplicate")
        target1 = str(uuid.uuid4())
        target2 = str(uuid.uuid4())
        
        try:
            # Start keepalive on first target
            assert manager.start_keepalive(target1)
            
            # Should not be able to start keepalive on second target
            assert not manager.start_keepalive(target2)
            
        finally:
            # Clean up
            manager.stop_keepalive()
            force_release_lock(target1)
            force_release_lock(target2)
            
    def test_keepalive_without_initial_lock_fails(self):
        """Test that keepalive fails if the initial lock cannot be acquired."""
        manager1 = DistributedLockManager(lock_owner="test-owner-1")
        manager2 = DistributedLockManager(lock_owner="test-owner-2")
        target_uuid = str(uuid.uuid4())
        
        try:
            # First manager acquires lock
            assert manager1.acquire_lock(target_uuid)
            
            # Second manager should not be able to start keepalive
            assert not manager2.start_keepalive(target_uuid)
            assert not manager2.is_keepalive_active
            
        finally:
            # Clean up
            manager1.release_lock(target_uuid)
            
    def test_stop_keepalive_when_none_running(self):
        """Test that stopping keepalive when none is running doesn't error."""
        manager = DistributedLockManager(lock_owner="test-no-keepalive")
        
        # Should not raise an exception
        manager.stop_keepalive()
        assert not manager.is_keepalive_active 
import pytest

from saq.local_locking import LocalLockError, lock_local

@pytest.mark.unit
def test_local_lock():
    with lock_local("test"):
        with pytest.raises(LocalLockError):
            with lock_local("test"):
                pass
        
        with lock_local("other"):
            pass
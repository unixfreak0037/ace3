import pytest

from tests.saq.helpers import close_test_comms, open_test_comms

@pytest.fixture
def test_comms():
    open_test_comms()
    yield
    close_test_comms()
from os import F_TEST
import pytest

from saq.observables.generator import create_observable, create_observable_from_dict

@pytest.mark.unit
def test_create_observable_from_dict():
    assert create_observable_from_dict(create_observable(F_TEST, "test").json).value == "test"
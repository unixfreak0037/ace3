
from saq.event import AutoCloseCriteria, load_auto_close_criteria

import pytest

@pytest.mark.unit
@pytest.mark.parametrize("conf_name,event_names,expected_result,raises_error", [
    ("name1", [ "name1" ], True, False), # exact match
    ("name1", [ "name1", "name2" ], True, False), # multiple names
    ("name1", [ "name3", "name2" ], False, False), # does not match name
])
def test_match(conf_name: str, event_names: list[str], expected_result: bool, raises_error: bool):
    assert AutoCloseCriteria(conf_name).matches(event_names) == expected_result

@pytest.mark.unit
@pytest.mark.parametrize("content, expected_result", [
    ("", []),
    ("""
criteria:
    - threat_name: name
""", [AutoCloseCriteria("name")])
])
def test_load_auto_close_criteria(content: str, expected_result: list[AutoCloseCriteria], tmpdir):
    with open(tmpdir / "test.yml", "w") as fp:
        fp.write(content)

    assert load_auto_close_criteria(tmpdir / "test.yml") == expected_result


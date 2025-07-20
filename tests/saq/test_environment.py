import pytest

from saq.environment import GlobalEnvironmentSetting, g, g_boolean, g_dict, g_int, g_list, set_g

@pytest.mark.unit
def test_g(monkeypatch):
    import saq.environment
    monkeypatch.setitem(saq.environment.GLOBAL_ENV, "test", GlobalEnvironmentSetting(
        name="test",
        value=None,
        description="test"
    ))

    assert g("test") is None
    set_g("test", "value")
    assert g("test") == "value"

    set_g("test", 1)
    assert g_int("test") == 1

    set_g("test", True)
    assert g_boolean("test") == True

    set_g("test", [1])
    assert g_list("test") == [1]

    set_g("test", {"value": 1})
    assert g_dict("test") == {"value": 1}

    set_g("test", "1")
    assert g_int("test") != 1
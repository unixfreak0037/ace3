import pytest

from saq.gui import node_translate_gui, translate_alert_redirect

@pytest.mark.unit
def test_node_translate_gui(monkeypatch):
    config = {}
    def mock_get_config():
        return config

    import saq.configuration.config
    monkeypatch.setattr(saq.configuration.config, "get_config", mock_get_config)
    assert node_translate_gui(None) is None
    assert node_translate_gui("node") == "node"
    config["node_translation_gui"] = {}
    assert node_translate_gui("node") == "node"
    config["node_translation_gui"]["node"] = "test"
    assert node_translate_gui("node") == "test"
    assert node_translate_gui("other node") == "other node"

@pytest.mark.parametrize("url,source_node,target_node,expected_url",[
    ("https://source/ace/analysis?direct=blah", "source", "target", "https://target/ace/analysis?direct=blah"),
    ("https://source:443/ace/analysis?direct=blah", "source:443", "target", "https://target/ace/analysis?direct=blah"),
    ("https://source/ace/analysis?direct=blah", "source", "target:5000", "https://target:5000/ace/analysis?direct=blah"),
    ("https://invalid/ace/analysis?direct=blah", "unknown", "target", "https://target/ace/analysis?direct=blah"),
])
@pytest.mark.unit
def test_translate_alert_redirect(url: str, source_node: str, target_node: str, expected_url: str, caplog):
    assert translate_alert_redirect(url, source_node, target_node) == expected_url
    if source_node == "unknown":
        assert "unexpected source_node in " in caplog.text
    else:
        assert "unexpected source_node in " not in caplog.text

import configparser
import pytest

from saq.analysis import Analysis, RootAnalysis
from saq.configuration import get_config
from saq.constants import F_TEST
from saq.engine.core import Engine
from saq.modules import AnalysisModule
from saq.engine.adapter import EngineAdapter
from saq.filesystem.adapter import FileSystemAdapter
from saq.modules.context import AnalysisModuleContext
from tests.saq.test_util import create_test_context

def get_mock_config(config_data: dict):
    config = configparser.ConfigParser()
    return config.read_dict(config_data)

@pytest.mark.unit
def test_accepts(monkeypatch, test_context):
    get_config()["analysis_module_test"] = {
        "module": "saq.modules.base_module",
        "class": "AnalysisModule"
    }
    module = AnalysisModule(context=test_context)
    root = RootAnalysis()
    obs = root.add_observable_by_spec(F_TEST, "test")

    # generated analysis type
    assert module.generated_analysis_type is None
    assert not module.accepts(obs)

    class MockAnalysis(Analysis):
        pass

    class MockAnalysisModule(AnalysisModule):
        @property
        def generated_analysis_type(self):
            return MockAnalysis

        @property
        def valid_observable_types(self):
            return F_TEST

    get_config()["analysis_module_mock"] = {
        "module": str(MockAnalysisModule.__module__),
        "class": str(MockAnalysisModule.__name__)
    }

    # requires detection path
    get_config()["analysis_module_mock"]["requires_detection_path"] = "yes"
    module = MockAnalysisModule(context=test_context)
    assert not module.accepts(obs)
    obs.add_detection_point("test")
    assert module.accepts(obs)

@pytest.mark.unit
def test_invalid_alert_type(monkeypatch, test_context):
    get_config()["analysis_module_test"] = {
        "module": "saq.modules.base_module",
        "class": "AnalysisModule"
    }
    module = AnalysisModule(context=test_context)
    root = RootAnalysis(alert_type="test")
    obs = root.add_observable_by_spec(F_TEST, "test")

    # generated analysis type
    assert module.generated_analysis_type is None
    assert not module.accepts(obs)

    class MockAnalysis(Analysis):
        pass

    class MockAnalysisModule(AnalysisModule):
        @property
        def generated_analysis_type(self):
            return MockAnalysis

        @property
        def valid_observable_types(self):
            return F_TEST

    get_config()["analysis_module_mock"] = {
        "module": str(MockAnalysisModule.__module__),
        "class": str(MockAnalysisModule.__name__)
    }

    module = MockAnalysisModule(context=create_test_context(root=root))
    assert module.accepts(obs)

    # single invalid alert type
    get_config()["analysis_module_mock"]["invalid_alert_types"] = "test"
    module = MockAnalysisModule(context=create_test_context(root=root))
    assert not module.accepts(obs)

    # multiple invalid alert types
    get_config()["analysis_module_mock"]["invalid_alert_types"] = "blah,test"
    module = MockAnalysisModule(context=create_test_context(root=root))
    assert not module.accepts(obs)
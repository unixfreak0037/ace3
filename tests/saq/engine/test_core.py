import pytest

from saq.configuration.config import get_config
from saq.constants import CONFIG_ANALYSIS_MODE_CLEANUP, CONFIG_ANALYSIS_MODE_PREFIX, CONFIG_ANALYSIS_MODULE_ENABLED, CONFIG_ANALYSIS_MODULE_MODULE_GROUPS, CONFIG_DISABLED_MODULES, F_TEST
from saq.engine.core import Engine, EngineState
from saq.engine.configuration_manager import ConfigurationManager, get_analysis_module_config
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker_manager import WorkerManager
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.test import BasicTestAnalysis, BasicTestAnalyzer

ANALYIS_MODE_TEST = "test"

@pytest.mark.parametrize("included, excluded, mode, expected_result", [
    ([], [], "test_1", True), # any mode supported
    (["test_1"], [], "test_1", True), # directly supported
    (["test_1"], [], "test_2", False), # not specifically supported
    ([], ["test_1"], "test_1", False), # specifically excluded
    ([], ["test_1"], "test_2", True), # outside exclusion
])
@pytest.mark.unit
def test_is_analysis_mode_supported(included, excluded, mode, expected_result):
    engine = Engine(config=EngineConfiguration(local_analysis_modes=included, excluded_analysis_modes=excluded))
    assert engine.configuration_manager.is_analysis_mode_supported(mode) == expected_result

@pytest.mark.unit
def test_default_engine():
    engine = Engine()
    assert engine.state == EngineState.INITIALIZING
    assert isinstance(engine.config, EngineConfiguration)
    assert isinstance(engine.configuration_manager, ConfigurationManager)
    assert isinstance(engine.node_manager, NodeManagerInterface)
    assert isinstance(engine.worker_manager, WorkerManager)

@pytest.mark.unit
def test_add_analysis_module(monkeypatch, test_context):
    engine = Engine()

    analysis_module = AnalysisModuleAdapter(BasicTestAnalyzer())
    engine.configuration_manager.add_analysis_module(analysis_module)

    assert engine.configuration_manager.analysis_modules == [analysis_module]
    assert engine.configuration_manager.analysis_module_name_mapping == { get_analysis_module_config(analysis_module).name: analysis_module }
    assert engine.configuration_manager.analysis_mode_mapping == { engine.config.default_analysis_mode: [analysis_module] }

    # verification failure
    def mock_verify_environment(*args, **kwargs):
        raise RuntimeError()

    engine.configuration_manager._initialize_mappings()
    with monkeypatch.context() as context:
        context.setattr(analysis_module, "verify_environment", mock_verify_environment)
        with pytest.raises(RuntimeError):
            engine.configuration_manager.add_analysis_module(analysis_module)


@pytest.mark.integration
def test_initialize_modules(test_context):
    engine = Engine()

    # by default all modules are disabled in the config so nothing should be loaded
    assert not engine.configuration_manager.analysis_modules
    assert not engine.configuration_manager.analysis_module_name_mapping
    assert engine.configuration_manager.analysis_mode_mapping == { engine.config.default_analysis_mode: [] }

    # enable one of them to be loaded
    engine.configuration_manager._get_analysis_module_config(AnalysisModuleAdapter(BasicTestAnalyzer()))[CONFIG_ANALYSIS_MODULE_ENABLED] = "yes"

    engine.configuration_manager.load_modules()

    assert len(engine.configuration_manager.analysis_modules) == 1
    assert len(engine.configuration_manager.analysis_module_name_mapping) == 1
    # this one is mapped to three different groups
    assert len(engine.configuration_manager.analysis_mode_mapping) == 3
    for analysis_modules in engine.configuration_manager.analysis_mode_mapping.values():
        assert len(analysis_modules) == 1
        assert analysis_modules[0].generated_analysis_type == BasicTestAnalysis

@pytest.mark.integration
def test_initialize_modules_missing_cleanup(test_context):
    config = get_analysis_module_config(AnalysisModuleAdapter(BasicTestAnalyzer()))
    config[CONFIG_ANALYSIS_MODULE_ENABLED] = "yes"

    # missing cleanup section logs as error, should still load
    engine = Engine()
    del get_config()[f"{CONFIG_ANALYSIS_MODE_PREFIX}{engine.config.default_analysis_mode}"][CONFIG_ANALYSIS_MODE_CLEANUP]
    engine.configuration_manager.load_modules()
    assert len(engine.configuration_manager.analysis_modules) == 1

@pytest.mark.integration
def test_initialize_modules_invalid_references(test_context):
    config = get_analysis_module_config(AnalysisModuleAdapter(BasicTestAnalyzer()))
    config[CONFIG_ANALYSIS_MODULE_ENABLED] = "yes"

    engine = Engine()
    mode_config = get_config()[f"{CONFIG_ANALYSIS_MODE_PREFIX}{engine.config.default_analysis_mode}"]
    # logs the error and skips the reference
    mode_config[CONFIG_ANALYSIS_MODULE_MODULE_GROUPS] = "invalid_group_name"
    # logs the error and continues
    mode_config["analysis_module_invalid_reference"] = {}
    
    # logs the error and continues
    get_config()["module_group_unittest"]["analysis_module_invalid_reference"] = {}
    engine.configuration_manager.load_modules()
    assert len(engine.configuration_manager.analysis_modules) == 1

@pytest.mark.integration
def test_initialize_modules_disabled_module(test_context):
    config = get_analysis_module_config(AnalysisModuleAdapter(BasicTestAnalyzer()))
    config[CONFIG_ANALYSIS_MODULE_ENABLED] = "yes"
    # disable this module specifically
    get_config()[CONFIG_DISABLED_MODULES][config.name] = "yes"

    engine = Engine()
    engine.configuration_manager.load_modules()
    assert len(engine.configuration_manager.analysis_modules) == 0

@pytest.mark.integration
def test_initialize_modules_module_load_failure(monkeypatch, test_context):
    config = get_analysis_module_config(AnalysisModuleAdapter(BasicTestAnalyzer()))
    assert config is not None
    config[CONFIG_ANALYSIS_MODULE_ENABLED] = "yes"

    def mock_load_module_from_config(*args, **kwargs):
        return None

    import saq.engine.module_loader
    monkeypatch.setattr(saq.engine.module_loader, "load_module_from_config", mock_load_module_from_config)

    engine = Engine()
    engine.configuration_manager.load_modules()
    # module fails to load
    assert len(engine.configuration_manager.analysis_modules) == 0

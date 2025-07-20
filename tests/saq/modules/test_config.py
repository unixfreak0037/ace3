import pytest
from unittest.mock import Mock

from saq.modules.config import AnalysisModuleConfig
from saq.modules.config_backend import DictConfigBackend


class MockAnalysisModule:
    """Mock analysis module for testing."""
    
    def __init__(self, module_name="test.module", class_name="TestModule", instance=None):
        self.__module__ = module_name
        self.__class__.__name__ = class_name
        self._instance = instance


@pytest.mark.unit
def test_analysis_module_config_with_dict_backend():
    """Test AnalysisModuleConfig with dictionary-based configuration backend."""
    
    # Create test configuration data
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule",
            "enabled": "yes",
            "priority": "5",
            "maximum_analysis_time": "300",
            "cooldown_period": "30",
            "cache": "true",
            "version": "2",
            "valid_observable_types": "file,url,ipv4",
            "required_tags": "tag1,tag2",
            "requires_detection_path": "false",
            "exclude_test1": "file:test.txt",
            "exclude_test2": "url:http://example.com",
            "expect_test1": "file:expected.txt"
        },
        "global": {
            "maximum_analysis_time": "600"
        },
        "observable_exclusions": {
            "exclude1": "file:global_exclude.txt"
        }
    }
    
    # Create backend and module
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    # Test basic properties
    assert config.priority == 5
    assert config.maximum_analysis_time == 300
    assert config.cooldown_period == 30
    assert config.cache is True
    assert config.version == 2
    assert config.requires_detection_path is False
    
    # Test list properties
    assert config.valid_observable_types == ["file", "url", "ipv4"]
    assert config.required_tags == ["tag1", "tag2"]
    
    # Test exclusions
    exclusions = config.observable_exclusions
    assert "file" in exclusions
    assert "test.txt" in exclusions["file"]
    assert "global_exclude.txt" in exclusions["file"]
    assert "url" in exclusions
    assert "http://example.com" in exclusions["url"]
    
    # Test expected observables
    expected = config.expected_observables
    assert "file" in expected
    assert "expected.txt" in expected["file"]


@pytest.mark.unit
def test_analysis_module_config_with_instance():
    """Test AnalysisModuleConfig with instanced modules."""
    
    config_data = {
        "analysis_module_test_instance1": {
            "module": "test.module",
            "class": "TestModule",
            "instance": "instance1",
            "priority": "1"
        },
        "analysis_module_test_instance2": {
            "module": "test.module", 
            "class": "TestModule",
            "instance": "instance2",
            "priority": "2"
        },
        "global": {
            "maximum_analysis_time": "600"
        }
    }
    
    backend = DictConfigBackend(config_data)
    
    # Test instance1
    module1 = MockAnalysisModule(instance="instance1")
    config1 = AnalysisModuleConfig(module1, backend)
    assert config1.priority == 1
    assert config1.instance == "instance1"
    
    # Test instance2
    module2 = MockAnalysisModule(instance="instance2")
    config2 = AnalysisModuleConfig(module2, backend)
    assert config2.priority == 2
    assert config2.instance == "instance2"


@pytest.mark.unit
def test_analysis_module_config_missing_section():
    """Test AnalysisModuleConfig when configuration section is missing."""
    
    config_data = {
        "global": {
            "maximum_analysis_time": "600"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)

    # now this works!
    assert config.config_section_name == "analysis_module_TestModule"


@pytest.mark.unit
def test_analysis_module_config_fallback_values():
    """Test AnalysisModuleConfig fallback values."""
    
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule"
            # No other values provided - should use fallbacks
        },
        "global": {
            "maximum_analysis_time": "600"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    # Test fallback values
    assert config.priority == 10  # default fallback
    assert config.maximum_analysis_time == 600  # from global config
    assert config.cooldown_period == 60  # default fallback
    assert config.cache is False  # default fallback
    assert config.version == 1  # default fallback
    assert config.requires_detection_path is False  # default fallback
    
    # Test None/empty list fallbacks
    assert config.valid_observable_types is None
    assert config.valid_queues is None
    assert config.invalid_queues is None
    assert config.invalid_alert_types is None
    assert config.required_directives == []
    assert config.required_tags == []


@pytest.mark.unit
def test_config_section_interface():
    """Test the ConfigSection interface methods."""
    
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule",
            "test_key": "test_value",
            "test_int": "42",
            "test_bool": "true"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    section = config.config_section
    
    # Test interface methods
    assert section.name == "analysis_module_test"
    assert section.get("test_key") == "test_value"
    assert section.get("missing_key", "default") == "default"
    assert section.getint("test_int") == 42
    assert section.getboolean("test_bool") is True
    assert "test_key" in section
    assert "missing_key" not in section
    assert section["test_key"] == "test_value"
    
    # Test keys and items
    keys = section.keys()
    assert "module" in keys
    assert "class" in keys
    assert "test_key" in keys
    
    items = section.items()
    assert ("test_key", "test_value") in items


@pytest.mark.unit
def test_config_utility_methods():
    """Test the utility methods on AnalysisModuleConfig."""
    
    config_data = {
        "analysis_module_test": {
            "module": "test.module",
            "class": "TestModule",
            "test_string": "hello",
            "test_int": "123",
            "test_bool": "yes"
        }
    }
    
    backend = DictConfigBackend(config_data)
    module = MockAnalysisModule()
    config = AnalysisModuleConfig(module, backend)
    
    # Test utility methods
    assert config.get_config_value("test_string") == "hello"
    assert config.get_config_value("missing", "default") == "default"
    assert config.get_config_int("test_int") == 123
    assert config.get_config_boolean("test_bool") is True
    assert config.has_config_key("test_string") is True
    assert config.has_config_key("missing") is False
    
    # Test verification methods
    config.verify_config_exists("test_string")  # Should not raise
    
    with pytest.raises(KeyError):
        config.verify_config_exists("missing_key")
    
    config.verify_config_item_has_value("test_string")  # Should not raise
    
    with pytest.raises(KeyError):
        config.verify_config_item_has_value("missing_key") 
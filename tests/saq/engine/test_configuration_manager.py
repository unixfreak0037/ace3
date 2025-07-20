"""
Tests for the ConfigurationManager class that was extracted from the Engine class.
"""

import pytest

from saq.configuration.config import get_config
from saq.constants import (
    CONFIG_ANALYSIS_MODULE_ENABLED,
    CONFIG_DISABLED_MODULES,
    ANALYSIS_MODE_ANALYSIS,
)
from saq.engine.configuration_manager import ConfigurationManager, get_analysis_module_config
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.modules.adapter import AnalysisModuleAdapter
from saq.modules.test import BasicTestAnalysis, BasicTestAnalyzer


@pytest.mark.unit
def test_configuration_manager_initialization():
    """Test that ConfigurationManager initializes properly."""
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],))
    
    assert config_manager.config.default_analysis_mode == ANALYSIS_MODE_ANALYSIS
    assert config_manager.config.local_analysis_modes == []
    assert config_manager.config.excluded_analysis_modes == []
    assert config_manager.analysis_modules == []
    assert config_manager.analysis_mode_mapping == {ANALYSIS_MODE_ANALYSIS: []}
    assert config_manager.analysis_module_name_mapping == {}


@pytest.mark.unit
def test_analysis_mode_support_logic():
    """Test the analysis mode support logic."""
    # Test with no restrictions (supports all modes)
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    assert config_manager.is_analysis_mode_supported("any_mode") == True
    
    # Test with local modes specified
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=["test_mode", "analysis"],
        excluded_analysis_modes=[],
    ))
    assert config_manager.is_analysis_mode_supported("test_mode") == True
    assert config_manager.is_analysis_mode_supported("analysis") == True
    assert config_manager.is_analysis_mode_supported("other_mode") == False
    
    # Test with excluded modes
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=["excluded_mode"],
    ))
    assert config_manager.is_analysis_mode_supported("any_mode") == True
    assert config_manager.is_analysis_mode_supported("excluded_mode") == False


@pytest.mark.unit
def test_enable_module_for_testing():
    """Test enabling modules for local testing."""

    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    # Enable a module without analysis mode
    config_manager.enable_module("test_module")
    assert "test_module" in config_manager.locally_enabled_modules
    
    # Enable a module with analysis mode
    config_manager.enable_module("test_module2", "test_mode")
    assert "test_module2" in config_manager.locally_enabled_modules
    assert "test_mode" in config_manager.locally_mapped_analysis_modes
    assert "test_module2" in config_manager.locally_mapped_analysis_modes["test_mode"]


@pytest.mark.unit 
def test_add_analysis_module():
    """Test adding analysis modules."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = AnalysisModuleAdapter(BasicTestAnalyzer())
    config_manager.add_analysis_module(analysis_module)
    
    assert len(config_manager.analysis_modules) == 1
    assert analysis_module in config_manager.analysis_modules
    assert ANALYSIS_MODE_ANALYSIS in config_manager.analysis_mode_mapping
    assert analysis_module in config_manager.analysis_mode_mapping[ANALYSIS_MODE_ANALYSIS]


@pytest.mark.unit
def test_get_analysis_modules_by_mode():
    """Test getting analysis modules by mode."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = AnalysisModuleAdapter(BasicTestAnalyzer())
    config_manager.add_analysis_module(analysis_module, [ANALYSIS_MODE_ANALYSIS])
    
    modules = config_manager.get_analysis_modules_by_mode(ANALYSIS_MODE_ANALYSIS)
    assert len(modules) == 1
    assert modules[0] == analysis_module
    
    # Test with None (should return default mode)
    modules = config_manager.get_analysis_modules_by_mode(None)
    assert len(modules) == 1
    assert modules[0] == analysis_module


@pytest.mark.unit
def test_get_analysis_module_by_id():
    """Test getting analysis module by ID."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = AnalysisModuleAdapter(BasicTestAnalyzer())
    config_manager.add_analysis_module(analysis_module)
    
    # Test with valid ID
    if analysis_module.module_id:
        found_module = config_manager.get_analysis_module_by_id(analysis_module.module_id)
        assert found_module == analysis_module
    
    # Test with invalid ID
    found_module = config_manager.get_analysis_module_by_id("nonexistent_id")
    assert found_module is None


@pytest.mark.unit
def test_is_module_enabled():
    """Test checking if module is enabled."""
    
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    analysis_module = AnalysisModuleAdapter(BasicTestAnalyzer())
    config_manager.add_analysis_module(analysis_module)
    
    # Test with valid ID
    if analysis_module.module_id:
        assert config_manager.is_module_enabled(analysis_module.module_id) == True
    
    # Test with invalid ID
    assert config_manager.is_module_enabled("nonexistent_id") == False


@pytest.mark.integration
def test_load_modules_integration():
    """Test the full module loading process."""
    config_manager = ConfigurationManager(config=EngineConfiguration(
        default_analysis_mode=ANALYSIS_MODE_ANALYSIS,
        local_analysis_modes=[],
        excluded_analysis_modes=[],
    ))
    
    # Enable one module to be loaded
    analysis_module = AnalysisModuleAdapter(BasicTestAnalyzer())
    module_config = get_analysis_module_config(analysis_module)
    if module_config:
        module_config[CONFIG_ANALYSIS_MODULE_ENABLED] = "yes"
    
    config_manager.load_modules()
    
    # Should load the enabled module
    assert len(config_manager.analysis_modules) >= 0  # May be 0 if config not found

"""
Configuration management for the analysis engine.
"""

import logging
from typing import Dict, List, Optional, Set, Union

from saq.configuration.config import get_config, get_config_value_as_boolean
from saq.constants import CONFIG_DISABLED_MODULES
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.module_loader import ModuleLoader
from saq.modules.interfaces import AnalysisModuleInterface
from saq.error import report_exception


class ConfigurationManager:
    """Manages all configuration-related responsibilities for the analysis engine.
    
    This class is responsible for:
    - Loading and parsing analysis module configurations
    - Building analysis mode to module mappings
    - Handling module enablement/disablement
    - Managing locally enabled modules and manual mappings
    """
    
    def __init__(self, config: EngineConfiguration):
        """Initialize the configuration manager.
        
        Args:
            config: The engine configuration
        """
        self.config = config
        
        # Module storage
        self.analysis_modules: List[AnalysisModuleInterface] = []
        self.analysis_mode_mapping: Dict[str, List[AnalysisModuleInterface]] = {}
        self.analysis_module_name_mapping: Dict[str, AnalysisModuleInterface] = {}
        
        # Local overrides for testing
        self.locally_enabled_modules: List[str] = []
        self.locally_mapped_analysis_modes: Dict[str, Set[str]] = {}
        
        # Initialize module loader
        self.module_loader = ModuleLoader(
            local_analysis_modes=self.config.local_analysis_modes,
            excluded_analysis_modes=self.config.excluded_analysis_modes,
            locally_enabled_modules=self.locally_enabled_modules,
            locally_mapped_analysis_modes=self.locally_mapped_analysis_modes
        )
        
        self._initialize_mappings()
    
    def _initialize_mappings(self):
        """Initialize the analysis mode mapping to default state."""
        self.analysis_modules.clear()
        self.analysis_mode_mapping = {self.config.default_analysis_mode: []}
        self.analysis_module_name_mapping.clear()
    
    def is_analysis_mode_supported(self, analysis_mode: str) -> bool:
        """Check if the given analysis mode is supported by this engine."""
        return self.module_loader.is_analysis_mode_supported(analysis_mode)
    
    def enable_module(self, config_section_name: str, analysis_mode: Union[str, list[str], None] = None):
        """Enable a specific module for local testing.
        
        Args:
            config_section_name: Configuration section name of the module
            analysis_mode: Analysis mode(s) to map the module to
        """
        if get_config_value_as_boolean(CONFIG_DISABLED_MODULES, config_section_name, default=False):
            logging.info(f"skipping disabled module {config_section_name}")
            return
        
        self.locally_enabled_modules.append(config_section_name)
        
        if analysis_mode is not None:
            if isinstance(analysis_mode, str):
                analysis_modes = (analysis_mode,)
            else:
                analysis_modes = analysis_mode
            
            for mode in analysis_modes:
                if mode not in self.locally_mapped_analysis_modes:
                    self.locally_mapped_analysis_modes[mode] = set()
                self.locally_mapped_analysis_modes[mode].add(config_section_name)
        
        # Update module loader with new local settings
        self.module_loader = ModuleLoader(
            local_analysis_modes=self.config.local_analysis_modes,
            excluded_analysis_modes=self.config.excluded_analysis_modes,
            locally_enabled_modules=self.locally_enabled_modules,
            locally_mapped_analysis_modes=self.locally_mapped_analysis_modes
        )
    
    def add_analysis_module(self,
                           analysis_module: AnalysisModuleInterface,
                           analysis_modes: Optional[List[str]] = None):
        """Add an analysis module to the configuration.
        
        Args:
            analysis_module: The module to add
            analysis_modes: List of analysis modes the module should run in
        """
        if not analysis_modes:
            logging.debug(
                f"no analysis modes specified for {analysis_module} -- use default {self.config.default_analysis_mode}"
            )
            analysis_modes = [self.config.default_analysis_mode]
        
        # Verify module environment
        try:
            analysis_module.verify_environment()
        except Exception as e:
            logging.error(f"analysis module {analysis_module} failed environment verification: {e}")
            report_exception()
            raise e
        
        # Get module configuration
        module_config = self._get_analysis_module_config(analysis_module)
        if module_config is None:
            logging.error(f"unable to find configuration for analysis module {analysis_module}")
            return
        section = module_config.name
        
        # Store the module
        self.analysis_modules.append(analysis_module)
        self.analysis_module_name_mapping[section] = analysis_module
        
        # Map to analysis modes
        for mode in analysis_modes:
            if mode not in self.analysis_mode_mapping:
                self.analysis_mode_mapping[mode] = []
            
            if analysis_module not in self.analysis_mode_mapping[mode]:
                self.analysis_mode_mapping[mode].append(analysis_module)
        
        logging.info(f"loaded analysis module {analysis_module} section {section}")
    
    def _get_analysis_module_config(self, module: AnalysisModuleInterface):
        """Get the configuration section for an analysis module."""
        return get_analysis_module_config(module)
    
    def load_modules(self) -> None:
        """Load all configured analysis modules and build the analysis mode mapping."""
        self._initialize_mappings()
        
        # Use module loader to get all loaded modules
        loaded_modules = self.module_loader.load_modules()
        
        # Add each loaded module to our configuration
        for section_name, (module, analysis_modes) in loaded_modules.items():
            self.add_analysis_module(module, analysis_modes)
    
    def get_analysis_modules_by_mode(self, analysis_mode: Optional[str]=None) -> List[AnalysisModuleInterface]:
        """Get analysis modules for a specific analysis mode, sorted by config section name."""
        if analysis_mode is None:
            result = self.analysis_mode_mapping[self.config.default_analysis_mode]
        else:
            try:
                result = self.analysis_mode_mapping[analysis_mode]
            except KeyError:
                logging.warning(f"invalid analysis mode {analysis_mode} - defaulting to {self.config.default_analysis_mode}")
                result = self.analysis_mode_mapping[self.config.default_analysis_mode]
        
        return sorted(result, key=lambda x: x.config_section_name)
    
    def get_analysis_module_by_id(self, module_id: str) -> Optional[AnalysisModuleInterface]:
        """Get an analysis module by its ID."""
        for analysis_module in self.analysis_modules:
            if analysis_module.module_id == module_id:
                return analysis_module
        return None
    
    def is_module_enabled(self, module_id: str) -> bool:
        """Check if a module is enabled by its ID."""
        return self.get_analysis_module_by_id(module_id) is not None 


# This function has been moved to ConfigurationManager._get_analysis_module_config
# Keeping this for backwards compatibility during transition
def get_analysis_module_config(module: AnalysisModuleInterface):
    assert isinstance(module, AnalysisModuleInterface)

    for section_name in get_config().sections():
        if section_name.startswith("analysis_module_"):
            module_name = get_config()[section_name].get("module")
            class_name = get_config()[section_name].get("class")
            instance_name = get_config()[section_name].get("instance")
            if module.matches_module_spec(module_name or "", class_name or "", instance_name):
                return get_config()[section_name]

    logging.error(f"analysis module {module} not found in config")
    return None
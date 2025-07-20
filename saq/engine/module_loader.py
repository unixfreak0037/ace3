"""
Module loading functionality for the analysis engine.

This module provides the ModuleLoader class that handles all
module loading responsibilities that were previously embedded
in the ConfigurationManager class, following the Single Responsibility Principle.
"""

import logging
from typing import Dict, List, Optional, Set

from saq.configuration.adapter import ConfigAdapter
from saq.configuration.config import (
    get_config,
    get_config_value_as_boolean,
    get_config_value_as_list,
)
from saq.constants import (
    CONFIG_ANALYSIS_MODE_CLEANUP,
    CONFIG_ANALYSIS_MODE_PREFIX,
    CONFIG_ANALYSIS_MODULE_ENABLED,
    CONFIG_ANALYSIS_MODULE_MODULE_GROUPS,
    CONFIG_ANALYSIS_MODULE_PREFIX,
    CONFIG_DISABLED_MODULES,
    CONFIG_MODULE_GROUP_PREFIX,
)
from saq.engine.adapter import EngineAdapter
from saq.filesystem.adapter import FileSystemAdapter
from saq.modules.adapter import load_module_from_config
from saq.modules.context import AnalysisModuleContext
from saq.modules.interfaces import AnalysisModuleInterface
from saq.error import report_exception


class ModuleLoader:
    """Handles loading analysis modules from configuration.
    
    This class is responsible for:
    - Finding all module sections that should be loaded
    - Building analysis mode to module section mappings
    - Loading individual modules from configuration
    - Determining which analysis modes modules should run in
    """
    
    def __init__(self, 
                 local_analysis_modes: List[str],
                 excluded_analysis_modes: List[str],
                 locally_enabled_modules: List[str],
                 locally_mapped_analysis_modes: Dict[str, Set[str]]):
        """Initialize the module loader.
        
        Args:
            engine_adapter: Adapter for engine dependencies
            local_analysis_modes: List of analysis modes supported locally
            excluded_analysis_modes: List of analysis modes to exclude
            locally_enabled_modules: List of modules enabled for local testing
            locally_mapped_analysis_modes: Local analysis mode mappings for testing
        """
        self.local_analysis_modes = local_analysis_modes
        self.excluded_analysis_modes = excluded_analysis_modes
        self.locally_enabled_modules = locally_enabled_modules
        self.locally_mapped_analysis_modes = locally_mapped_analysis_modes
    
    def load_modules(self) -> Dict[str, tuple[AnalysisModuleInterface, List[str]]]:
        """Load all configured analysis modules and return them with their analysis modes.
        
        Returns:
            Dict mapping section names to (module, analysis_modes) tuples
        """
        # Build analysis mode to module section mapping
        analysis_mode_section_names_map = self._build_analysis_mode_mapping()
        
        # Get all unique module sections to load
        analysis_module_sections = set()
        for mode_sections in analysis_mode_section_names_map.values():
            analysis_module_sections.update(mode_sections)
        
        # Add locally enabled modules
        analysis_module_sections.update(self.locally_enabled_modules)
        
        logging.debug(f"loading {len(analysis_module_sections)} analysis modules...")
        
        # Load each module
        loaded_modules = {}
        for section_name in analysis_module_sections:
            if not self._should_load_module(section_name):
                continue
            
            module = self._load_single_module(section_name)
            if module is None:
                continue
            
            # Determine which analysis modes this module runs in
            analysis_modes = []
            for mode, config_sections in analysis_mode_section_names_map.items():
                if section_name in config_sections:
                    analysis_modes.append(mode)
            
            loaded_modules[section_name] = (module, analysis_modes)
        
        logging.debug(f"finished loading {len(loaded_modules)} modules")
        return loaded_modules
    
    def is_analysis_mode_supported(self, analysis_mode: str) -> bool:
        """Check if the given analysis mode is supported."""
        if analysis_mode in self.excluded_analysis_modes:
            return False
        
        if not self.local_analysis_modes:
            return True
            
        return analysis_mode in self.local_analysis_modes
    
    def _build_analysis_mode_mapping(self) -> Dict[str, Set[str]]:
        """Build mapping of analysis modes to their module configuration sections."""
        analysis_mode_section_names_map: Dict[str, Set[str]] = {}

        unsupported_modes = []
        
        # Process each analysis mode configuration section
        for section_name in get_config().sections():
            if not section_name.startswith(CONFIG_ANALYSIS_MODE_PREFIX):
                continue
            
            mode = section_name[len(CONFIG_ANALYSIS_MODE_PREFIX):]
            
            # Validate cleanup configuration
            if CONFIG_ANALYSIS_MODE_CLEANUP not in get_config()[section_name]:
                logging.error(f"{section_name} missing cleanup key in configuration file")
            
            # Check if mode is supported
            if not self.is_analysis_mode_supported(mode):
                unsupported_modes.append(mode)
                continue
            
            analysis_mode_section_names_map[mode] = set()
            
            # Add modules from module groups
            self._add_modules_from_groups(section_name, mode, analysis_mode_section_names_map)
            
            # Add/remove individual modules
            self._add_individual_modules(section_name, mode, analysis_mode_section_names_map)
            
            # Add locally mapped modules
            self._add_locally_mapped_modules(mode, analysis_mode_section_names_map)
        
        if unsupported_modes:
            logging.info(
                f"analysis modes {','.join(unsupported_modes)} is not supported by the engine "
                f"(local analysis modes: {','.join(self.local_analysis_modes) if self.local_analysis_modes else 'none'}) "
                f"(excluded analysis modes: {','.join(self.excluded_analysis_modes) if self.excluded_analysis_modes else 'none'})"
            )

        return analysis_mode_section_names_map
    
    def _add_modules_from_groups(self, section_name: str, mode: str, 
                                analysis_mode_section_names_map: Dict[str, Set[str]]):
        """Add modules from module groups to the analysis mode mapping."""
        for group_name in get_config_value_as_list(
            section_name,
            CONFIG_ANALYSIS_MODULE_MODULE_GROUPS,
            default=[],
            include_empty=False,
        ):
            group_section = f"{CONFIG_MODULE_GROUP_PREFIX}{group_name}"
            if group_section not in get_config():
                logging.error(f"{section_name} defines invalid module group {group_name}")
                continue
            
            # Add each module in the group
            for module_section in get_config()[group_section].keys():
                if module_section not in get_config():
                    logging.error(f"{group_section} references invalid analysis module {module_section}")
                    continue
                
                analysis_mode_section_names_map[mode].add(module_section)
    
    def _add_individual_modules(self, section_name: str, mode: str,
                               analysis_mode_section_names_map: Dict[str, Set[str]]):
        """Add or remove individual modules for an analysis mode."""
        for key_name in get_config()[section_name].keys():
            if not key_name.startswith(CONFIG_ANALYSIS_MODULE_PREFIX):
                continue
            
            analysis_module_name = key_name[len(CONFIG_ANALYSIS_MODULE_PREFIX):]
            if key_name not in get_config():
                logging.error(f"{section_name} references invalid analysis module {analysis_module_name}")
                continue
            
            # Add or remove based on boolean value
            if get_config_value_as_boolean(section_name, key_name):
                analysis_mode_section_names_map[mode].add(key_name)
            else:
                analysis_mode_section_names_map[mode].discard(key_name)
    
    def _add_locally_mapped_modules(self, mode: str, analysis_mode_section_names_map: Dict[str, Set[str]]):
        """Add locally mapped modules for testing."""
        if mode in self.locally_mapped_analysis_modes:
            for analysis_module_section in self.locally_mapped_analysis_modes[mode]:
                logging.debug(f"manual map for mode {mode} to {analysis_module_section}")
                analysis_mode_section_names_map[mode].add(analysis_module_section)
    
    def _should_load_module(self, section_name: str) -> bool:
        """Determine if a module should be loaded based on configuration."""
        if not self.locally_enabled_modules:
            # Check global disabled modules
            if get_config_value_as_boolean(CONFIG_DISABLED_MODULES, section_name, False):
                logging.debug(f"{section_name} is disabled")
                return False
            
            # Check module enabled flag
            if not get_config_value_as_boolean(section_name, CONFIG_ANALYSIS_MODULE_ENABLED, False):
                logging.debug(f"analysis module {section_name} disabled (globally)")
                return False
        else:
            # Check local enablement
            if section_name not in self.locally_enabled_modules:
                return False
        
        return True
    
    def _load_single_module(self, section_name: str) -> Optional[AnalysisModuleInterface]:
        """Load a single analysis module from configuration."""
        try:
            analysis_module = load_module_from_config(section_name)
            if analysis_module is None:
                logging.warning(f"load_module({section_name}) failed to return a value - skipping")
                return None
            
            return analysis_module
            
        except Exception as e:
            logging.error(f"failed to load analysis module {section_name}: {e}")
            report_exception()
            return None 
from datetime import timedelta
from functools import cached_property
import logging
from typing import Optional, Union

from saq.configuration.config import get_config, get_config_value, get_config_value_as_int
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_ANALYSIS_TIME, CONFIG_OBSERVABLE_EXCLUSIONS
from saq.modules.config_backend import ConfigBackend, ConfigSection, INIConfigBackend
from saq.util.time import create_timedelta


class AnalysisModuleConfig:
    """Handles all configuration-related responsibilities for AnalysisModule instances.
    
    This class decouples configuration management from the AnalysisModule class,
    following the Single Responsibility Principle.
    """
    
    def __init__(self, module_instance, config_backend: Optional[ConfigBackend] = None):
        """Initialize with a reference to the module instance for config lookup.
        
        Args:
            module_instance: The analysis module instance
            config_backend: Optional configuration backend. If None, uses INI backend.
        """
        self._module_instance = module_instance
        self._config_backend = config_backend or INIConfigBackend()
        self._observable_exclusions = None
        self._expected_observables = None
    
    @cached_property
    def config_section(self) -> ConfigSection:
        """Get the configuration section for this module."""
        result = self._get_analysis_module_config()
        if result is None:
            raise RuntimeError(
                f"cannot find config for analysis module {self._module_instance.__module__} "
                f"class {type(self._module_instance).__name__}"
            )
        return result
    
    @property
    def config_section_name(self) -> str:
        """Get the name of the configuration section."""
        return self.config_section.name
    
    @cached_property
    def instance(self) -> Optional[str]:
        """Get the instance name from configuration."""
        return self.config_section.get("instance")

    @property
    def module_id(self) -> Optional[str]:
        """Get the module id from configuration."""
        return self.config_section.get("id", fallback=None)
    
    @property
    def priority(self) -> int:
        """Get the module priority (lower numbers = higher priority)."""
        return self.config_section.getint("priority", fallback=10)
    
    @cached_property
    def observation_grouping_time_range(self) -> Optional[timedelta]:
        """Get the time range for grouping observations."""
        if "observation_grouping_time_range" in self.config_section:
            return create_timedelta(self.config_section["observation_grouping_time_range"])
        return None
    
    @property
    def automation_limit(self) -> Optional[int]:
        """Get the automation limit for this module."""
        return self.config_section.getint("automation_limit", fallback=None)
    
    @property
    def maximum_analysis_time(self) -> int:
        """Get the maximum analysis time in seconds."""
        return self.config_section.getint(
            "maximum_analysis_time", 
            fallback=self._config_backend.get_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_MAXIMUM_ANALYSIS_TIME)
        )
    
    @property
    def cooldown_period(self) -> int:
        """Get the cooldown period in seconds."""
        return self.config_section.getint("cooldown_period", fallback=60)
    
    @property
    def semaphore_name(self) -> Optional[str]:
        """Get the semaphore name for this module."""
        return self.config_section.get("semaphore")
    
    @property
    def file_size_limit(self) -> int:
        """Get the file size limit in bytes (0 = no limit)."""
        return self.config_section.getint("file_size_limit", fallback=0)
    
    @property
    def valid_observable_types(self) -> Union[str, list[str], None]:
        """Get the list of valid observable types for this module."""
        if "valid_observable_types" not in self.config_section:
            return None
        return [_.strip() for _ in self.config_section["valid_observable_types"].split(",")]
    
    @property
    def valid_queues(self) -> Optional[list[str]]:
        """Get the list of valid queues for this module."""
        if "valid_queues" not in self.config_section:
            return None
        return [_.strip() for _ in self.config_section["valid_queues"].split(",")]
    
    @property
    def invalid_queues(self) -> Optional[list[str]]:
        """Get the list of invalid queues for this module."""
        if "invalid_queues" not in self.config_section:
            return None
        return [_.strip() for _ in self.config_section["invalid_queues"].split(",")]
    
    @property
    def invalid_alert_types(self) -> Optional[list[str]]:
        """Get the list of invalid alert types for this module."""
        if "invalid_alert_types" not in self.config_section:
            return None
        return [_.strip() for _ in self.config_section["invalid_alert_types"].split(",")]
    
    @property
    def required_directives(self) -> list[str]:
        """Get the list of required directives for this module."""
        if "required_directives" not in self.config_section:
            return []
        return [_.strip() for _ in self.config_section["required_directives"].split(",")]
    
    @property
    def required_tags(self) -> list[str]:
        """Get the list of required tags for this module."""
        if "required_tags" not in self.config_section:
            return []
        return [_.strip() for _ in self.config_section["required_tags"].split(",")]
    
    @property
    def requires_detection_path(self) -> bool:
        """Check if this module requires observables to be on a detection path."""
        return self.config_section.getboolean("requires_detection_path", fallback=False)
    
    @property
    def cache(self) -> bool:
        """Check if caching is enabled for this module."""
        return self.config_section.getboolean("cache", fallback=False)
    
    @property
    def version(self) -> int:
        """Get the module version for caching purposes."""
        return self.config_section.getint("version", fallback=1)
    
    @property
    def cache_expiration(self) -> timedelta:
        """Get the cache expiration time."""
        if "cache_expiration" in self.config_section:
            return create_timedelta(self.config_section["cache_expiration"])
        return timedelta(hours=24)
    
    @property
    def observable_exclusions(self) -> dict:
        """Get the observable exclusions for this module."""
        if self._observable_exclusions is None:
            self._observable_exclusions = self._load_exclusions()
        return self._observable_exclusions
    
    @property
    def expected_observables(self) -> dict[str, set]:
        """Get the expected observables for this module."""
        if self._expected_observables is None:
            self._expected_observables = self._load_expected_observables()
        return self._expected_observables
    
    @property
    def is_grouped_by_time(self) -> bool:
        """Check if this module groups observations by time."""
        return self.observation_grouping_time_range is not None
    
    def _get_analysis_module_config(self) -> Optional[ConfigSection]:
        """Find the configuration section for this module."""
        for section_name in self._config_backend.sections():
            if section_name.startswith("analysis_module_"):
                section = self._config_backend.get_section(section_name)
                if section is None:
                    continue
                    
                module_name = section.get("module")
                class_name = section.get("class")
                instance_name = section.get("instance")
                
                if (module_name == self._module_instance.__module__ and 
                    class_name == type(self._module_instance).__name__):
                    
                    # Use the instance passed to the module constructor directly
                    module_instance = getattr(self._module_instance, '_instance', None)
                    if module_instance and instance_name != module_instance:
                        continue
                    
                    return section
        
        # If no configuration found, create a new one on-the-fly
        module_name = self._module_instance.__module__
        class_name = type(self._module_instance).__name__
        instance_name = getattr(self._module_instance, '_instance', None)
        
        # Create a unique section name
        section_name = f"analysis_module_{class_name}"
        if instance_name:
            section_name += f"_{instance_name}"
        
        # Create the new section in the config backend
        new_section = self._config_backend.create_section(section_name)
        new_section.set("module", module_name)
        new_section.set("class", class_name)
        if instance_name:
            new_section.set("instance", instance_name)
        
        logging.warning(f"created new analysis module config section {section_name} for {self._module_instance}")
        return new_section
    
    def _load_exclusions(self) -> dict:
        """Load observable exclusions from configuration."""
        exclusions = {}
        
        # Load module-specific exclusions
        for key in self.config_section.keys():
            if key.startswith("exclude_"):
                o_type, o_value = self.config_section[key].split(":", 1)
                if o_type == "observable_group":
                    # Load exclusion from observable group
                    logging.debug(f"loading exclusion list from observable group {o_value} for {self._module_instance}")
                    config_key = f"observable_group_{o_value}"
                    group_section = self._config_backend.get_section(config_key)
                    if group_section:
                        for group_key in group_section.keys():
                            if group_key.startswith("define_"):
                                group_o_type, group_o_value = group_section[group_key].split(":", 1)
                                self._add_observable_exclusion(exclusions, group_o_type, group_o_value)
                else:
                    self._add_observable_exclusion(exclusions, o_type, o_value)
        
        # Append global exclusions
        global_exclusions_section = self._config_backend.get_section(CONFIG_OBSERVABLE_EXCLUSIONS)
        if global_exclusions_section:
            for option_name in global_exclusions_section.keys():
                o_type, o_value = global_exclusions_section[option_name].split(":", 1)
                self._add_observable_exclusion(exclusions, o_type, o_value)
        
        return exclusions
    
    def _add_observable_exclusion(self, exclusions: dict, o_type: str, o_value: str):
        """Add an observable exclusion to the exclusions dict."""
        if o_type not in exclusions:
            exclusions[o_type] = []
        
        if o_value not in exclusions[o_type]:
            exclusions[o_type].append(o_value)
    
    def _load_expected_observables(self) -> dict[str, set]:
        """Load expected observables from configuration."""
        expected = {}
        
        for key in self.config_section.keys():
            if key.startswith("expect_"):
                o_type, o_value = self.config_section[key].split(":", 1)
                self._add_expected_observable(expected, o_type, o_value)
        
        return expected
    
    def _add_expected_observable(self, expected: dict, o_type: str, o_value: str):
        """Add an expected observable to the expected dict."""
        if o_type not in expected:
            expected[o_type] = set()
        
        expected[o_type].add(o_value)
        logging.debug(f"loaded expected observable type {o_type} value {o_value} for {self._module_instance}")
    
    def verify_config_exists(self, config_name: str):
        """Verify that a configuration option exists."""
        if config_name not in self.config_section:
            raise KeyError(f"module {self._module_instance} missing configuration item {config_name}")
    
    def verify_config_item_has_value(self, config_key: str):
        """Verify that a configuration option exists and has a value."""
        self.verify_config_exists(config_key)
        if not self.config_section[config_key]:
            raise TypeError(f"module {self._module_instance} configuration item {config_key} is not defined.")
    
    def get_config_value(self, key: str, fallback=None):
        """Get a configuration value with optional fallback."""
        return self.config_section.get(key, fallback)
    
    def get_config_int(self, key: str, fallback=None):
        """Get a configuration value as integer with optional fallback."""
        return self.config_section.getint(key, fallback=fallback)
    
    def get_config_boolean(self, key: str, fallback=None):
        """Get a configuration value as boolean with optional fallback."""
        return self.config_section.getboolean(key, fallback=fallback)
    
    def has_config_key(self, key: str) -> bool:
        """Check if a configuration key exists."""
        return key in self.config_section
    
    def get_config_keys(self):
        """Get all configuration keys."""
        return self.config_section.keys()
    
    def get_config_items(self):
        """Get all configuration items."""
        return self.config_section.items() 
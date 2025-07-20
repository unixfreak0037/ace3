from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union


class ConfigSection(ABC):
    """Abstract interface for a configuration section."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of this configuration section."""
        pass
    
    @abstractmethod
    def get(self, key: str, fallback: Optional[str] = None) -> Optional[str]:
        """Get a configuration value as string."""
        pass
    
    @abstractmethod
    def getint(self, key: str, fallback: Optional[int] = None) -> Optional[int]:
        """Get a configuration value as integer."""
        pass
    
    @abstractmethod
    def getboolean(self, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        """Get a configuration value as boolean."""
        pass
    
    @abstractmethod
    def keys(self) -> List[str]:
        """Get all configuration keys in this section."""
        pass
    
    @abstractmethod
    def items(self) -> List[tuple[str, str]]:
        """Get all configuration items as (key, value) pairs."""
        pass
    
    @abstractmethod
    def __contains__(self, key: str) -> bool:
        """Check if a key exists in this section."""
        pass
    
    @abstractmethod
    def __getitem__(self, key: str) -> str:
        """Get a configuration value by key."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: str) -> None:
        """Set a configuration value."""
        pass


class ConfigBackend(ABC):
    """Abstract interface for configuration backends."""
    
    @abstractmethod
    def sections(self) -> List[str]:
        """Get all section names."""
        pass
    
    @abstractmethod
    def get_section(self, section_name: str) -> Optional[ConfigSection]:
        """Get a configuration section by name."""
        pass
    
    @abstractmethod
    def has_section(self, section_name: str) -> bool:
        """Check if a section exists."""
        pass
    
    @abstractmethod
    def get_value(self, section: str, key: str, fallback: Optional[str] = None) -> Optional[str]:
        """Get a configuration value from a specific section."""
        pass
    
    @abstractmethod
    def get_value_as_int(self, section: str, key: str, fallback: Optional[int] = None) -> Optional[int]:
        """Get a configuration value as integer from a specific section."""
        pass
    
    @abstractmethod
    def get_value_as_boolean(self, section: str, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        """Get a configuration value as boolean from a specific section."""
        pass
    
    @abstractmethod
    def create_section(self, section_name: str) -> ConfigSection:
        """Create a new configuration section."""
        pass


class DictConfigSection(ConfigSection):
    """Dictionary-based implementation of ConfigSection for testing."""
    
    def __init__(self, name: str, data: Dict[str, Any]):
        self._name = name
        self._data = data
    
    @property
    def name(self) -> str:
        return self._name
    
    def get(self, key: str, fallback: Optional[str] = None) -> Optional[str]:
        value = self._data.get(key, fallback)
        return str(value) if value is not None else None
    
    def getint(self, key: str, fallback: Optional[int] = None) -> Optional[int]:
        value = self._data.get(key, fallback)
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return fallback
    
    def getboolean(self, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        value = self._data.get(key, fallback)
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "on")
        return bool(value)
    
    def keys(self) -> List[str]:
        return list(self._data.keys())
    
    def items(self) -> List[tuple[str, str]]:
        return [(k, str(v)) for k, v in self._data.items()]
    
    def __contains__(self, key: str) -> bool:
        return key in self._data
    
    def __getitem__(self, key: str) -> str:
        value = self._data[key]
        return str(value) if value is not None else ""
    
    def set(self, key: str, value: str) -> None:
        """Set a configuration value."""
        self._data[key] = value


class DictConfigBackend(ConfigBackend):
    """Dictionary-based configuration backend for testing."""
    
    def __init__(self, config_data: Dict[str, Dict[str, Any]]):
        self._config_data = config_data
    
    def sections(self) -> List[str]:
        return list(self._config_data.keys())
    
    def get_section(self, section_name: str) -> Optional[ConfigSection]:
        if section_name not in self._config_data:
            return None
        return DictConfigSection(section_name, self._config_data[section_name])
    
    def has_section(self, section_name: str) -> bool:
        return section_name in self._config_data
    
    def get_value(self, section: str, key: str, fallback: Optional[str] = None) -> Optional[str]:
        if section not in self._config_data:
            return fallback
        value = self._config_data[section].get(key, fallback)
        return str(value) if value is not None else None
    
    def get_value_as_int(self, section: str, key: str, fallback: Optional[int] = None) -> Optional[int]:
        if section not in self._config_data:
            return fallback
        value = self._config_data[section].get(key, fallback)
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return fallback
    
    def get_value_as_boolean(self, section: str, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        if section not in self._config_data:
            return fallback
        value = self._config_data[section].get(key, fallback)
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "on")
        return bool(value)
    
    def create_section(self, section_name: str) -> ConfigSection:
        """Create a new configuration section."""
        if section_name not in self._config_data:
            self._config_data[section_name] = {}
        return DictConfigSection(section_name, self._config_data[section_name])


class INIConfigSection(ConfigSection):
    """Wrapper around configparser.SectionProxy to implement ConfigSection interface."""
    
    def __init__(self, section_proxy):
        self._section_proxy = section_proxy
    
    @property
    def name(self) -> str:
        return self._section_proxy.name
    
    def get(self, key: str, fallback: Optional[str] = None) -> Optional[str]:
        return self._section_proxy.get(key, fallback)
    
    def getint(self, key: str, fallback: Optional[int] = None) -> Optional[int]:
        return self._section_proxy.getint(key, fallback=fallback)
    
    def getboolean(self, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        return self._section_proxy.getboolean(key, fallback=fallback)
    
    def keys(self) -> List[str]:
        return list(self._section_proxy.keys())
    
    def items(self) -> List[tuple[str, str]]:
        return list(self._section_proxy.items())
    
    def __contains__(self, key: str) -> bool:
        return key in self._section_proxy
    
    def __getitem__(self, key: str) -> str:
        return self._section_proxy[key]
    
    def set(self, key: str, value: str) -> None:
        """Set a configuration value."""
        self._section_proxy[key] = value


class INIConfigBackend(ConfigBackend):
    """INI-based configuration backend using the existing configuration system."""
    
    def __init__(self, config_parser=None):
        if config_parser is None:
            from saq.configuration.config import get_config
            self._config_parser = get_config()
        else:
            self._config_parser = config_parser
    
    def sections(self) -> List[str]:
        return self._config_parser.sections()
    
    def get_section(self, section_name: str) -> Optional[ConfigSection]:
        if section_name not in self._config_parser:
            return None
        return INIConfigSection(self._config_parser[section_name])
    
    def has_section(self, section_name: str) -> bool:
        return section_name in self._config_parser
    
    def get_value(self, section: str, key: str, fallback: Optional[str] = None) -> Optional[str]:
        from saq.configuration.config import get_config_value
        return get_config_value(section, key, fallback)
    
    def get_value_as_int(self, section: str, key: str, fallback: Optional[int] = None) -> Optional[int]:
        from saq.configuration.config import get_config_value_as_int
        return get_config_value_as_int(section, key, fallback)
    
    def get_value_as_boolean(self, section: str, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        from saq.configuration.config import get_config_value_as_boolean
        return get_config_value_as_boolean(section, key, fallback)
    
    def create_section(self, section_name: str) -> ConfigSection:
        """Create a new configuration section."""
        if not self._config_parser.has_section(section_name):
            self._config_parser.add_section(section_name)
        return INIConfigSection(self._config_parser[section_name]) 
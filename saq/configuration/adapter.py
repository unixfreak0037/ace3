from saq.configuration.config import get_config_value, get_config_value_as_boolean, get_config_value_as_int


from typing import Any


class ConfigAdapter:
    """Adapter that implements ConfigInterface using the existing config system."""

    def get_config_value(self, section: str, key: str, default=None) -> Any:
        return get_config_value(section, key, default=default)

    def get_config_value_as_int(self, section: str, key: str, default=None) -> int:
        return get_config_value_as_int(section, key, default=default)

    def get_config_value_as_boolean(self, section: str, key: str, default=None) -> bool:
        return get_config_value_as_boolean(section, key, default=default)
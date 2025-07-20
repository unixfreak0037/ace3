from typing import Any, Protocol


class ConfigInterface(Protocol):
    """Interface for configuration access."""

    def get_config_value(self, section: str, key: str, default=None) -> Any:
        """Get configuration value."""
        ...

    def get_config_value_as_int(self, section: str, key: str, default=None) -> int:
        """Get configuration value as integer."""
        ...

    def get_config_value_as_boolean(self, section: str, key: str, default=None) -> bool:
        """Get configuration value as boolean."""
        ...
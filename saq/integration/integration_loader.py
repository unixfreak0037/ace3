from dataclasses import dataclass
import logging
import os
import sys
import importlib

from saq.configuration.config import get_config
from saq.error import report_exception

@dataclass
class IntegrationConfig:
    name: str
    enabled: bool
    location: str
    entrypoint: str
    config: str

def get_all_integrations() -> list[IntegrationConfig]:
    """Returns a list of all integrations."""
    integrations: list[IntegrationConfig] = []
    for section in get_config().sections():
        if section.startswith("integration_"):
            name = get_config().get(section, "name")
            enabled = get_config().getboolean(section, "enabled")
            location = get_config().get(section, "location")
            entrypoint = get_config().get(section, "entrypoint")
            config = get_config().get(section, "config")
            integrations.append(IntegrationConfig(name=name, enabled=enabled, location=location, entrypoint=entrypoint, config=config))

    return integrations


def load_integrations() -> bool:
    """Loads all integrations. Returns True if all defined and enabled integrations were loaded successfully."""
    defined_integrations = get_all_integrations()
    result = True

    for integration in defined_integrations:
        if not integration.enabled:
            continue

        try:
            if not load_from_directory(integration):
                logging.error(f"failed to load integration {integration.name}")
                result = False
        except Exception as e:
            logging.error(f"failed to load integration {integration.name}: {e}")
            report_exception()
            result = False

    return result


def load_from_directory(config: IntegrationConfig) -> bool:
    """Loads an ACE integration from a local directory.

    Args:
        integration_name: The name of the integration.
        dir_path: The path to the integration directory.
        entry_point: The entry point to the integration. This is the name of the module to import.

    Returns:
        True if the integration was loaded successfully, False otherwise.
    """
    if not os.path.exists(config.location):
        raise RuntimeError(f"integration {config.name} directory {config.location} does not exist")

    if not os.path.isdir(config.location):
        raise RuntimeError(f"integration {config.name} directory {config.location} is not a directory")

    # modify the PYTHONPATH to include the integration directory
    if config.location not in sys.path:
        sys.path.insert(0, config.location)

    # import the python module
    importlib.import_module(config.entrypoint)

    # load the defined configuration
    config_path = os.path.join(config.location, config.config)
    if not os.path.exists(config_path):
        raise RuntimeError(f"integration {config.name} configuration file {config_path} does not exist")

    get_config().load_file(config_path)
    logging.info(f"loaded integration {config.name} configuration from {config_path}")

    # NOTE right now we are not calling verify() on the config
    return True

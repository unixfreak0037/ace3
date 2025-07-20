import configparser
import logging
import os
import sys
from typing import Any, Optional

from saq.configuration.parser import load_configuration

# global configuration singleton
CONFIG = None

def get_config() -> configparser.ConfigParser:
    """Returns the global configuration object."""
    assert isinstance(CONFIG, configparser.ConfigParser)
    return CONFIG

def get_config_value(section: str, name: str, default: Optional[Any]=None) -> str:
    if section not in get_config():
        return default

    return get_config()[section].get(name, default)

def get_config_value_as_int(section: str, name: str, default: Optional[Any]=None) -> int:
    if section not in get_config():
        return default

    return get_config()[section].getint(name, default)

def get_config_value_as_boolean(section: str, name: str, default: Optional[Any]=None) -> bool:
    if section not in get_config():
        return default

    return get_config()[section].getboolean(name, default)

def get_config_value_as_list(section: str, name: str, default: Optional[Any]=None, sep: Optional[str]=",", include_empty: Optional[bool]=True) -> list[str]:
    if section not in get_config():
        return default

    value = get_config_value(section, name)
    if value is None:
        return default

    return [_.strip() for _ in value.split(sep) if include_empty or _]

def set_config(config: configparser.ConfigParser):
    assert isinstance(config, configparser.ConfigParser)

    global CONFIG
    if CONFIG:
        sys.stderr.write("global CONFIG object changing\n")

    CONFIG = config

def initialize_configuration(config_paths: Optional[list[str]]=None):
    global CONFIG

    # load configuration files
    # defaults to $SAQ_HOME/etc/saq.ini
    if config_paths is None:
        config_paths = []
    
    CONFIG_PATHS = []

    # add any config files specified in SAQ_CONFIG_PATHS env var (command separated)
    if "SAQ_CONFIG_PATHS" in os.environ:
        for config_path in os.environ["SAQ_CONFIG_PATHS"].split(","):
            config_path = config_path.strip()
            #if not os.path.isabs(config_path):
                #config_path = os.path.join(get_base_dir(), config_path)
            if not os.path.exists(config_path):
                sys.stderr.write(f"WARNING: config path {config_path} specified in SAQ_CONFIG_PATHS env var does not exist\n")
            else:
                if config_path not in CONFIG_PATHS:
                    CONFIG_PATHS.append(config_path)

    # and then add any specified on the command line
    for config_path in config_paths:
        if not os.path.isabs(config_path):
            #config_path = os.path.join(get_base_dir(), config_path)
            if not os.path.exists(config_path):
                sys.stderr.write(f"WARNING: config path {config_path} specified on the command line does not exist\n")
            else:
                if config_path not in CONFIG_PATHS:
                    CONFIG_PATHS.append(config_path)

    # XXX get rid of this logic
    #if UNIT_TESTING:
        # unit testing loads different configurations
        #CONFIG_PATHS.append(os.path.join(SAQ_HOME, 'etc', 'saq.unittest.default.ini'))
        #CONFIG_PATHS.append(os.path.join(SAQ_HOME, 'etc', 'saq.unittest.ini'))
    #else:
        #CONFIG_PATHS.append(os.path.join(SAQ_HOME, 'etc', 'saq.ini'))

    try:
        CONFIG = load_configuration()
    except Exception as e:
        sys.stderr.write(f"ERROR: unable to load configuration: {e}")
        raise
        #sys.exit(1) # TODO replace with exception for unit testing
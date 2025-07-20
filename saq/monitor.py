from dataclasses import dataclass
from datetime import datetime
import logging
import sys
from threading import RLock
from typing import Any, Optional

from saq.configuration.config import get_config_value_as_boolean
from saq.constants import CONFIG_MONITOR, CONFIG_MONITOR_USE_CACHE, CONFIG_MONITOR_USE_LOGGING, CONFIG_MONITOR_USE_STDERR, CONFIG_MONITOR_USE_STDOUT

@dataclass
class Monitor:
    category: str
    name: str
    data_type: type
    description: str

@dataclass
class CacheEntry:
    identifier: str
    value: Any
    time: datetime

def _format_message(monitor: Monitor, value: Any, identifier: Optional[str]=None) -> str:
    identifier_message = ""
    if identifier is not None:
        identifier_message = f" <{identifier}> "

    return "MONITOR [{}] ({}){}: {}".format(monitor.category, monitor.name, identifier_message, value)

class MonitorEmitter:
    def __init__(self):
        self.use_logging = False
        self.use_stdout = False
        self.use_stderr = False
        self.use_cache = False

        # in-memory cache
        self.cache = {}
        self.cache_lock = RLock()

    def emit_cache(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        with self.cache_lock:
            if monitor.category not in self.cache:
                self.cache[monitor.category] = {}

            self.cache[monitor.category][monitor.name] = CacheEntry(identifier, value, datetime.now())

    def emit_logging(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        logging.debug(_format_message(monitor, value, identifier))
        return True

    def emit_stdout(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        print(_format_message(monitor, value, identifier))
        return True

    def emit_stderr(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        sys.stderr.write(_format_message(monitor, value, identifier))
        sys.stderr.write("\n")
        return True

    def emit(self, monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
        assert isinstance(value, monitor.data_type)
        
        if self.use_cache:
            self.emit_cache(monitor, value, identifier)

        if self.use_logging:
            self.emit_logging(monitor, value, identifier)

        if self.use_stdout:
            self.emit_stdout(monitor, value, identifier)

        if self.use_stderr:
            self.emit_stderr(monitor, value, identifier)

        return True

    def dump_cache(self, fp):
        with self.cache_lock:
            for category in sorted(self.cache.keys()):
                for name in sorted(self.cache[category].keys()):
                    cache_entry = self.cache[category][name]
                    identifier_str = ""
                    if cache_entry.identifier:
                        identifier_str = f":{cache_entry.identifier}"

                    fp.write(f"[{category}] ({name}{identifier_str}): {cache_entry.value} @ {cache_entry.time}\n")

global_emitter = MonitorEmitter()

def get_emitter() -> MonitorEmitter:
    return global_emitter

def reset_emitter():
    global global_emitter
    global_emitter = MonitorEmitter()

def emit_monitor(monitor: Monitor, value: Any, identifier: Optional[str]=None) -> bool:
    assert isinstance(value, monitor.data_type)
    return get_emitter().emit(monitor, value, identifier)

def enable_monitor_logging():
    get_emitter().use_logging = True

def enable_monitor_stdout():
    get_emitter().use_stdout = True

def enable_monitor_stderr():
    get_emitter().use_stderr = True

def enable_monitor_cache():
    get_emitter().use_cache = True

def initialize_monitoring():
    reset_emitter()

    if get_config_value_as_boolean(CONFIG_MONITOR, CONFIG_MONITOR_USE_STDOUT):
        enable_monitor_stdout()

    if get_config_value_as_boolean(CONFIG_MONITOR, CONFIG_MONITOR_USE_STDERR):
        enable_monitor_stderr()

    if get_config_value_as_boolean(CONFIG_MONITOR, CONFIG_MONITOR_USE_LOGGING):
        enable_monitor_logging()

    if get_config_value_as_boolean(CONFIG_MONITOR, CONFIG_MONITOR_USE_CACHE):
        enable_monitor_cache()
from configparser import SectionProxy
from dataclasses import dataclass, field

from saq.constants import CONFIG_COLLECTION_COLLECTION_FREQUENCY, CONFIG_COLLECTION_DELETE_FILES, CONFIG_COLLECTION_ERROR_DIR, CONFIG_COLLECTION_FORCE_API, CONFIG_COLLECTION_INCOMING_DIR, CONFIG_COLLECTION_PERSISTENCE_CLEAR_SECONDS, CONFIG_COLLECTION_PERSISTENCE_DIR, CONFIG_COLLECTION_PERSISTENCE_EXPIRATION_SECONDS, CONFIG_COLLECTION_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS, CONFIG_COLLECTION_QUEUE, CONFIG_COLLECTION_TUNING_UPDATE_FREQUENCY, CONFIG_COLLECTION_WORKLOAD_TYPE, QUEUE_DEFAULT

DEFAULT_DELETE_FILES = False
DEFAULT_COLLECTION_FREQUENCY = 1
DEFAULT_PERSISTENCE_DIR = "var/collection/persistence"
DEFAULT_INCOMING_DIR = "var/collection/incoming"
DEFAULT_ERROR_DIR = "var/collection/error"
DEFAULT_FORCE_API = False
DEFAULT_TUNING_UPDATE_FREQUENCY = "00:01:00"
DEFAULT_PERSISTENCE_CLEAR_SECONDS = 60
DEFAULT_PERSISTENCE_EXPIRATION_SECONDS = 24*60*60
DEFAULT_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS = 4*60*60

@dataclass
class CollectorServiceConfiguration:
    """Configuration for a collector service."""
    workload_type: str
    queue: str = field(default=QUEUE_DEFAULT)
    delete_files: bool = field(default=DEFAULT_DELETE_FILES)
    collection_frequency: int = field(default=DEFAULT_COLLECTION_FREQUENCY)
    persistence_dir: str = field(default=DEFAULT_PERSISTENCE_DIR)
    incoming_dir: str = field(default=DEFAULT_INCOMING_DIR)
    error_dir: str = field(default=DEFAULT_ERROR_DIR)
    force_api: bool = field(default=DEFAULT_FORCE_API)
    tuning_update_frequency: str = field(default=DEFAULT_TUNING_UPDATE_FREQUENCY)
    persistence_clear_seconds: int = field(default=DEFAULT_PERSISTENCE_CLEAR_SECONDS)
    persistence_expiration_seconds: int = field(default=DEFAULT_PERSISTENCE_EXPIRATION_SECONDS)
    persistence_unmodified_expiration_seconds: int = field(default=DEFAULT_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS)

    @staticmethod
    def from_dict(config: dict) -> "CollectorServiceConfiguration":
        """Create a CollectorServiceConfiguration from a dictionary."""
        return CollectorServiceConfiguration(
            workload_type=config[CONFIG_COLLECTION_WORKLOAD_TYPE],
            queue=config.get(CONFIG_COLLECTION_QUEUE, QUEUE_DEFAULT),
            delete_files=config.get(CONFIG_COLLECTION_DELETE_FILES, DEFAULT_DELETE_FILES),
            collection_frequency=config.get(CONFIG_COLLECTION_COLLECTION_FREQUENCY, DEFAULT_COLLECTION_FREQUENCY),
            persistence_dir=config.get(CONFIG_COLLECTION_PERSISTENCE_DIR, DEFAULT_PERSISTENCE_DIR),
            incoming_dir=config.get(CONFIG_COLLECTION_INCOMING_DIR, DEFAULT_INCOMING_DIR),
            error_dir=config.get(CONFIG_COLLECTION_ERROR_DIR, DEFAULT_ERROR_DIR),
            force_api=config.get(CONFIG_COLLECTION_FORCE_API, DEFAULT_FORCE_API),
            tuning_update_frequency=config.get(CONFIG_COLLECTION_TUNING_UPDATE_FREQUENCY, DEFAULT_TUNING_UPDATE_FREQUENCY),
            persistence_clear_seconds=config.get(CONFIG_COLLECTION_PERSISTENCE_CLEAR_SECONDS, DEFAULT_PERSISTENCE_CLEAR_SECONDS),
            persistence_expiration_seconds=config.get(CONFIG_COLLECTION_PERSISTENCE_EXPIRATION_SECONDS, DEFAULT_PERSISTENCE_EXPIRATION_SECONDS),
            persistence_unmodified_expiration_seconds=config.get(CONFIG_COLLECTION_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS, DEFAULT_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS),
        )

    @staticmethod
    def from_config(config: SectionProxy) -> "CollectorServiceConfiguration":
        """Create a CollectorServiceConfiguration from a config dictionary."""
        return CollectorServiceConfiguration(
            workload_type=config[CONFIG_COLLECTION_WORKLOAD_TYPE],
            queue=config.get(CONFIG_COLLECTION_QUEUE, QUEUE_DEFAULT),
            delete_files=config.getboolean(CONFIG_COLLECTION_DELETE_FILES, fallback=DEFAULT_DELETE_FILES),
            collection_frequency=config.getint(CONFIG_COLLECTION_COLLECTION_FREQUENCY, fallback=DEFAULT_COLLECTION_FREQUENCY),
            persistence_dir=config.get(CONFIG_COLLECTION_PERSISTENCE_DIR, fallback=DEFAULT_PERSISTENCE_DIR),
            incoming_dir=config.get(CONFIG_COLLECTION_INCOMING_DIR, fallback=DEFAULT_INCOMING_DIR),
            error_dir=config.get(CONFIG_COLLECTION_ERROR_DIR, fallback=DEFAULT_ERROR_DIR),
            force_api=config.getboolean(CONFIG_COLLECTION_FORCE_API, fallback=DEFAULT_FORCE_API),
            tuning_update_frequency=config.get(CONFIG_COLLECTION_TUNING_UPDATE_FREQUENCY, fallback=DEFAULT_TUNING_UPDATE_FREQUENCY),
            persistence_clear_seconds=config.getint(CONFIG_COLLECTION_PERSISTENCE_CLEAR_SECONDS, fallback=DEFAULT_PERSISTENCE_CLEAR_SECONDS),
            persistence_expiration_seconds=config.getint(CONFIG_COLLECTION_PERSISTENCE_EXPIRATION_SECONDS, fallback=DEFAULT_PERSISTENCE_EXPIRATION_SECONDS),
            persistence_unmodified_expiration_seconds=config.getint(CONFIG_COLLECTION_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS, fallback=DEFAULT_PERSISTENCE_UNMODIFIED_EXPIRATION_SECONDS),
        )
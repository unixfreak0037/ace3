# this is a fall back device to be used if the network semaphore is unavailable
# semaphores defined in the configuration file
import logging
from threading import RLock
from saq.configuration.config import get_config, get_config_value_as_int
from saq.constants import CONFIG_NETWORK_SEMAPHORE
from saq.network_semaphore.logging import LoggingSemaphore


defined_fallback_semaphores = {} # key = semaphore name, value = LoggingSemaphore(count)
# semaphores defined during runtime (these are deleted after release to 0)
undefined_fallback_semaphores = {} # key = semaphore name, value = LoggingSemaphore(count)
undefined_fallback_semaphores_lock = RLock()

def get_defined_fallback_semaphores() -> dict[str, LoggingSemaphore]:
    return defined_fallback_semaphores

def get_undefined_fallback_semaphores() -> dict[str, LoggingSemaphore]:
    return defined_fallback_semaphores

def get_undefined_fallback_semaphores_lock() -> RLock:
    return undefined_fallback_semaphores_lock

def add_undefined_fallback_semaphore(name, count=1):
    """Adds the given semaphore as an undefined fallback semaphore. Returns the added semaphore object."""
    with undefined_fallback_semaphores_lock:
        undefined_fallback_semaphores[name] = LoggingSemaphore(count)
        logging.info(f"added undefined fallback semaphore {name} with limit {count}")
        return undefined_fallback_semaphores[name]

def maintain_undefined_semaphores():
    with undefined_fallback_semaphores_lock:
        targets = []
        for semaphore_name in undefined_fallback_semaphores.keys():
            if undefined_fallback_semaphores[semaphore_name].count == 0:
                targets.append(semaphore_name)

        for target in targets:
            logging.debug(f"finished with undefined semaphore {target}")
            del undefined_fallback_semaphores[target]

        if undefined_fallback_semaphores:
            logging.info(f"tracking {len(undefined_fallback_semaphores)} undefined semaphores")

def initialize_fallback_semaphores():
    """This needs to be called once at the very beginning of starting ACE."""

    global defined_fallback_semaphores
    defined_fallback_semaphores = {}

    # we need some fallback functionality for when the network semaphore server is down
    # these semaphores serve that purpose
    for key in get_config()[CONFIG_NETWORK_SEMAPHORE].keys():
        if key.startswith('semaphore_'):
            semaphore_name = key[len('semaphore_'):]
            # the configuration settings for the network semaphore specify how many connections
            # are allowed to a specific resource at once, globally
            # so if we unable to coordinate globally, the fall back is to divide the available
            # number of resources between all the engines evenly
            # that's what this next equation is for
            fallback_limit = get_config_value_as_int(CONFIG_NETWORK_SEMAPHORE, key)
            if fallback_limit < 1:
                fallback_limit = 1

            defined_fallback_semaphores[semaphore_name] = LoggingSemaphore(fallback_limit)
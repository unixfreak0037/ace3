import logging
from app.blueprints import events
from saq.configuration.config import get_config

@events.context_processor
def send_to_hosts():
    hosts = {}
    try:
        config_keys = [x for x in get_config().keys() if x.startswith('send_to_')]
        hosts = [get_config()[x] for x in config_keys]
    except Exception as e:
        logging.error(f"no hosts properly configured to send to: {e}")

    return dict(send_to_hosts=hosts)
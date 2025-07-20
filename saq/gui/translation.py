import logging
from urllib.parse import urlparse, urlunparse
from saq.configuration.config import get_config_value
from saq.constants import CONFIG_NODE_TRANSLATION_GUI


def node_translate_gui(node:str) -> str:
    """Looks up the node in the node_translation_gui section and returns the value.
    If the node does not exist, then node is returned.
    This is used to translate a node location to a DNS name that can be used in a URL."""
    return get_config_value(CONFIG_NODE_TRANSLATION_GUI, node, default=node)

def translate_alert_redirect(url: str, source_node: str, target_node: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc != source_node:
        logging.warning("unexpected source_node in translate_alert_direction: %s should be %s", parsed.netloc, source_node)

    # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    return urlunparse((parsed.scheme, target_node, parsed.path, parsed.params, parsed.query, parsed.fragment))
from saq.configuration import get_config, get_config_value, get_config_value_as_boolean, get_config_value_as_int
from saq.constants import CONFIG_DISPOSITION_BENIGN, CONFIG_DISPOSITION_CSS, CONFIG_DISPOSITION_MALICIOUS, CONFIG_DISPOSITION_RANK, CONFIG_DISPOSITION_SHOW_SAVE_TO_EVENT, CONFIG_VALID_DISPOSITIONS, DISPOSITION_OPEN, VALID_DISPOSITIONS

# XXX refactor this

DISPOSITIONS = {}

def get_dispositions():
    return DISPOSITIONS

def initialize_dispositions():
    # initialize dispositions
    # XXX why the hell is this here?
    global DISPOSITIONS
    DISPOSITIONS = {
        DISPOSITION_OPEN: {
            "rank": 0,
            "css": "light",
            "show_save_to_event": False,
        }
    }
    for disposition in VALID_DISPOSITIONS:
        if get_config_value_as_boolean(CONFIG_VALID_DISPOSITIONS, disposition):
            DISPOSITIONS[disposition.upper()] = {
                "rank": get_config_value_as_int(CONFIG_DISPOSITION_RANK, disposition, default=0),
                "css": get_config_value(CONFIG_DISPOSITION_CSS, disposition, default="special"),
                "show_save_to_event": get_config_value_as_boolean(CONFIG_DISPOSITION_SHOW_SAVE_TO_EVENT, disposition, default=False),
            }

    global BENIGN_DISPOSITIONS
    BENIGN_DISPOSITIONS = []
    for disposition in get_config()[CONFIG_DISPOSITION_BENIGN]:
        if get_config_value_as_boolean(CONFIG_DISPOSITION_BENIGN, disposition):
            BENIGN_DISPOSITIONS.append(disposition.upper())

    global MALICIOUS_DISPOSITIONS
    MALICIOUS_DISPOSITIONS = []
    for disposition in get_config()[CONFIG_DISPOSITION_MALICIOUS]:
        if get_config_value_as_boolean(CONFIG_DISPOSITION_MALICIOUS, disposition):
            MALICIOUS_DISPOSITIONS.append(disposition.upper())

def get_disposition_rank(disposition: str) -> int:
    return DISPOSITIONS.get(disposition, {}).get("rank", 0)

def get_malicious_dispositions() -> list[str]:
    return MALICIOUS_DISPOSITIONS

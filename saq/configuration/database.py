import base64

from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_ENCRYPTED_PASSWORDS_DB

# the following functions use the database table `config` to store arbitrary key/value pairs
# TODO move this to a better service at some point


def set_database_config_value(key, value):
    from saq.database import get_db_connection
    from saq.configuration.config import get_config_value
    if isinstance(value, int):
        value = str(value)
    elif isinstance(value, str):
        pass
    elif isinstance(value, bytes):
        value = base64.b64encode(value)
    else:
        raise TypeError(f"invalid type {type(value)} specified for set_database_config_value")

    with get_db_connection(name=get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_ENCRYPTED_PASSWORDS_DB)) as db:
        c = db.cursor()
        c.execute("""
INSERT INTO `config` ( `key`, `value` ) VALUES ( %s, %s )
ON DUPLICATE KEY UPDATE `value` = %s""", (key, value, value))
        db.commit()

def get_database_config_value(key, type=str):
    from saq.database import get_db_connection
    from saq.configuration.config import get_config_value
    with get_db_connection(name=get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_ENCRYPTED_PASSWORDS_DB)) as db:
        c = db.cursor()
        c.execute("""SELECT `value` FROM `config` WHERE `key` = %s""", (key,))
        result = c.fetchone()
        if result:
            result = result[0]
        else:
            return None

        if type is not None:
            if type is bytes:
                result = base64.b64decode(result)
            else:
                result = type(result)

        return result

def delete_database_config_value(key):
    from saq.database import get_db_connection
    from saq.configuration.config import get_config_value
    with get_db_connection(name=get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_ENCRYPTED_PASSWORDS_DB)) as db:
        c = db.cursor()
        c.execute("""DELETE FROM `config` WHERE `key` = %s""", (key,))
        db.commit()
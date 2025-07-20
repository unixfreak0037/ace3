# vim: sw=4:ts=4:et
# configuration settings for the GUI

from functools import lru_cache
from saq.configuration import get_config, get_config_value, get_config_value_as_boolean, get_config_value_as_int, get_config_value_as_list
from saq.constants import CONFIG_DATABASE_ACE, CONFIG_DATABASE_DATABASE, CONFIG_DATABASE_HOSTNAME, CONFIG_DATABASE_MAX_ALLOWED_PACKET, CONFIG_DATABASE_PASSWORD, CONFIG_DATABASE_PORT, CONFIG_DATABASE_SSL_CA, CONFIG_DATABASE_SSL_CERT, CONFIG_DATABASE_SSL_KEY, CONFIG_DATABASE_UNIX_SOCKET, CONFIG_DATABASE_USERNAME, CONFIG_GLOBAL, CONFIG_GLOBAL_INSTANCE_NAME, CONFIG_GUI, CONFIG_GUI_AUTHENTICATION, CONFIG_GUI_DISPLAY_EVENTS, CONFIG_GUI_DISPLAY_METRICS, CONFIG_GUI_GOOGLE_ANALYTICS, CONFIG_GUI_NAVIGATION_TABS, CONFIG_GUI_SECRET_KEY, GUI_TABS, INSTANCE_TYPE_DEV, INSTANCE_TYPE_PRODUCTION, INSTANCE_TYPE_QA, INSTANCE_TYPE_UNITTEST
from saq.util import abs_path

def _get_secret_key():
    result = get_config_value(CONFIG_GUI, CONFIG_GUI_SECRET_KEY)
    if result:
        return result

    import string
    import random
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(64))

class Config:
    def __init__(self):
        self.SECRET_KEY = _get_secret_key()
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False

        self.INSTANCE_NAME = get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_INSTANCE_NAME)

        # GUI configurations for base template use
        self.GUI_DISPLAY_METRICS = get_config_value_as_boolean(CONFIG_GUI, CONFIG_GUI_DISPLAY_METRICS)
        self.GUI_DISPLAY_EVENTS = get_config_value_as_boolean(CONFIG_GUI, CONFIG_GUI_DISPLAY_EVENTS)
        self.AUTHENTICATION_ON = get_config_value_as_boolean(CONFIG_GUI, CONFIG_GUI_AUTHENTICATION)
        self.GOOGLE_ANALYTICS = get_config_value_as_boolean(CONFIG_GUI, CONFIG_GUI_GOOGLE_ANALYTICS)

        # also see lib/saq/database.py:initialize_database
        if get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_UNIX_SOCKET):
            self.SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@localhost/{database}?unix_socket={unix_socket}&charset=utf8mb4'.format(
                username=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_USERNAME),
                password=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_PASSWORD),
                unix_socket=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_UNIX_SOCKET),
                database=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_DATABASE))
        else:
            self.SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@{hostname}:{port}/{database}?charset=utf8mb4'.format(
                username=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_USERNAME),
                password=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_PASSWORD),
                hostname=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_HOSTNAME),
                port=get_config_value_as_int(CONFIG_DATABASE_ACE, CONFIG_DATABASE_PORT),
                database=get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_DATABASE))

        self.SQLALCHEMY_POOL_TIMEOUT = 30
        self.SQLALCHEMY_POOL_RECYCLE = 60 * 10 # 10 minute connection pool recycle

        # gets passed as **kwargs to create_engine call of SQLAlchemy
        # this is used by the non-flask applications to configure SQLAlchemy db connection
        self.SQLALCHEMY_DATABASE_OPTIONS = { 
            'pool_recycle': self.SQLALCHEMY_POOL_RECYCLE,
            'pool_timeout': self.SQLALCHEMY_POOL_TIMEOUT,
            'pool_size': 5,
            'connect_args': { 'init_command': 'SET NAMES utf8mb4' },
            'pool_pre_ping': True,
        }

        if get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_MAX_ALLOWED_PACKET):
            self.SQLALCHEMY_DATABASE_OPTIONS['connect_args']['max_allowed_packet'] = get_config_value_as_int(CONFIG_DATABASE_ACE, CONFIG_DATABASE_MAX_ALLOWED_PACKET)

        # are we using SSL for MySQL connections? (you should be)
        if not get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_UNIX_SOCKET):
            if get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_CA) \
            or get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_CERT) \
            or get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_KEY):
                ssl_options = { 'ca': abs_path(get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_CA)) }
                if get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_CERT):
                    ssl_options['cert'] = abs_path(get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_CERT))
                if get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_KEY):
                    ssl_options['key'] = abs_path(get_config_value(CONFIG_DATABASE_ACE, CONFIG_DATABASE_SSL_KEY))
                self.SQLALCHEMY_DATABASE_OPTIONS['connect_args']['ssl'] = ssl_options

    @property
    def GUI_TABS(self) -> list[str]:
        if get_config()['gui']['navigation_tabs'].strip().lower() == "all":
            return GUI_TABS
        else:
            return get_config_value_as_list(CONFIG_GUI, CONFIG_GUI_NAVIGATION_TABS)

    @staticmethod
    def init_app(app):
        pass

class ProductionConfig(Config):
    
    def __init__(self):
        super().__init__()
        self.DEBUG = False
        self.TEMPLATES_AUTO_RELOAD = False

class DevelopmentConfig(Config):

    def __init__(self):
        super().__init__()
        self.DEBUG = True
        self.TEMPLATES_AUTO_RELOAD = True

class UnitTestConfig(Config):

    def __init__(self):
        super().__init__()
        self.DEBUG = True
        self.TEMPLATES_AUTO_RELOAD = True

@lru_cache
def get_flask_config(name: str) -> Config:
    # the keys for this dict match the instance_type config setting in global section of etc/saq.ini
    if name == INSTANCE_TYPE_DEV:
        return DevelopmentConfig()
    elif name == INSTANCE_TYPE_PRODUCTION:
        return ProductionConfig()
    elif name == INSTANCE_TYPE_QA:
        return ProductionConfig()
    elif name == INSTANCE_TYPE_UNITTEST:
        return UnitTestConfig()
    else:
        raise ValueError("invalid instance type", name)

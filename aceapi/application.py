from aceapi.blueprints import register_blueprints
from saq.configuration import get_config, get_config_value
from saq.constants import CONFIG_API, CONFIG_API_SECRET_KEY, CONFIG_GLOBAL, CONFIG_GLOBAL_INSTANCE_NAME
from saq.database.pool import set_db

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event

from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util import abs_path

class CustomSQLAlchemy(SQLAlchemy):
    def apply_driver_hacks(self, app, info, options):
        # are we using SSL for MySQL connections? (you should be)
        SQLAlchemy.apply_driver_hacks(self, app, info, options)

def create_app(testing=False):
    class _config(object):
        SECRET_KEY = get_config_value(CONFIG_API, CONFIG_API_SECRET_KEY)
        SQLALCHEMY_TRACK_MODIFICATIONS = False

        INSTANCE_NAME = get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_INSTANCE_NAME)

        # also see lib/saq/database.py:initialize_database
        if get_config()['database_ace'].get('unix_socket', fallback=None):
            SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@{hostname}/{database}?unix_socket={unix_socket}&charset=utf8mb4'.format(
                username=get_config().get('database_ace', 'username'),
                password=get_config().get('database_ace', 'password'),
                hostname=get_config().get('database_ace', 'hostname'),
                database=get_config().get('database_ace', 'database'),
                unix_socket=get_config().get('database_ace', 'unix_socket'))
        else:
            SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://{username}:{password}@{hostname}:{port}/{database}?charset=utf8mb4'.format(
                username=get_config().get('database_ace', 'username'),
                password=get_config().get('database_ace', 'password'),
                hostname=get_config().get('database_ace', 'hostname'),
                port=get_config().get('database_ace', 'port'),
                database=get_config().get('database_ace', 'database'))

        SQLALCHEMY_POOL_TIMEOUT = 30
        SQLALCHEMY_POOL_RECYCLE = 60 * 10

        # gets passed as **kwargs to create_engine call of SQLAlchemy
        # this is used by the non-flask applications to configure SQLAlchemy db connection
        SQLALCHEMY_DATABASE_OPTIONS = { 
            'pool_recycle': SQLALCHEMY_POOL_RECYCLE,
            'pool_timeout': SQLALCHEMY_POOL_TIMEOUT,
            'pool_size': 5,
            'connect_args': { 'init_command': "SET NAMES utf8mb4" },
        }

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            # are we using SSL for MySQL connections? (you should be)
            if not get_config()['database_ace'].get('unix_socket', fallback=None):
                if get_config()['database_ace'].get('ssl_ca', fallback=None) \
                or get_config()['database_ace'].get('ssl_cert', fallback=None) \
                or get_config()['database_ace'].get('ssl_key', fallback=None):
                    ssl_options = { 'ca': abs_path(get_config()['database_ace']['ssl_ca']) }
                    if get_config()['database_ace'].get('ssl_cert', fallback=None):
                        ssl_options['cert'] = abs_path(get_config()['database_ace']['ssl_cert'])
                    if get_config()['database_ace'].get('ssl_key', fallback=None):
                        ssl_options['key'] = abs_path(get_config()['database_ace']['ssl_key'])
                    self.SQLALCHEMY_DATABASE_OPTIONS['connect_args']['ssl'] = ssl_options

    class _test_config(_config):
        TESTING = True

    flask_app = Flask(__name__)
    app_config = _test_config() if testing else _config()
    flask_app.config.from_object(app_config)

    db = CustomSQLAlchemy(engine_options=app_config.SQLALCHEMY_DATABASE_OPTIONS)
    if not testing:
        # XXX hack: tests will create test contexts but the database pool is global
        # we don't want to change it because things like collectors *also* manage the connections
        set_db(db.session)
    #set_g(G_DB, db)
    db.init_app(flask_app)

    with flask_app.app_context():
        @event.listens_for(db.engine, 'checkin')
        def checkin(dbapi_connection, connection_record):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, db.engine.pool.status())

        @event.listens_for(db.engine, 'checkout')
        def checkout(dbapi_connection, connection_record, connection_proxy):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, db.engine.pool.status())

    register_blueprints(flask_app)
    return flask_app

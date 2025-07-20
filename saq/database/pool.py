import collections
from contextlib import contextmanager
from datetime import datetime
import functools
import logging
import os
import sys
import threading
from typing import Any, Callable
import warnings

import pymysql
from sqlalchemy import create_engine, event

from saq.configuration.config import get_config
from saq.error import report_exception
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_DB_POOL_AVAILABLE_COUNT, MONITOR_DB_POOL_IN_USE_COUNT, MONITOR_SQLALCHEMY_DB_POOL_STATUS
from saq.util import abs_path, create_timedelta

from sqlalchemy.exc import DisconnectionError
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.orm.session import sessionmaker

DatabaseSession = None

def get_db() -> scoped_session:
    return DatabaseSession

def set_db(value):
    global DatabaseSession
    DatabaseSession = value

class _database_pool:
    def __init__(self, name):
        # the name of the database this is a pool for
        self.name = name
        # all the database connections that are available
        self.available = collections.deque()
        # all the database connections that are currently in use
        self.in_use = collections.deque()
        # the thread and process that created the pool
        self.tid = threading.get_ident()
        self.pid = os.getpid()
        # lock used to make changes to the queues
        self.lock = threading.RLock()

        config_section = f'database_{name}'
        section = get_config()[config_section]
        kwargs: dict[str, Any] = {
            'db': section['database'],
            'user': section['username'],
            'passwd': section['password'],
            'charset': 'utf8mb4',
        }

        if 'max_allowed_packet' in section:
            kwargs['max_allowed_packet'] = section.getint('max_allowed_packet')

        if 'hostname' in section:
            kwargs['host'] = section['hostname']

        if 'port' in section:
            kwargs['port'] = section.getint('port')
        
        if 'unix_socket' in section:
            kwargs['unix_socket'] = section['unix_socket']

        kwargs['init_command'] = 'SET NAMES utf8mb4'

        if 'ssl_ca' in section or 'ssl_key' in section or 'ssl_cert' in section:
            kwargs['ssl'] = {}

            if 'ssl_ca' in section and section['ssl_ca']:
                path = abs_path(section['ssl_ca'])
                if not os.path.exists(path):
                    logging.error("ssl_ca file {} does not exist (specified in {})".format(path, config_section))
                else:
                    kwargs['ssl']['ca'] = path

            if 'ssl_key' in section and section['ssl_key']:
                path = abs_path(section['ssl_key'])
                if not os.path.exists(path):
                    logging.error("ssl_key file {} does not exist (specified in {})".format(path, config_section))
                else:
                    kwargs['ssl']['key'] = path

            if 'ssl_cert' in section and section['ssl_cert']:
                path = section['ssl_cert']
                if not os.path.exists(path):
                    logging.error("ssl_cert file {} does not exist (specified in {})".format(path, config_section))
                else:
                    kwargs['ssl']['cert'] = path

        self.kwargs = kwargs

    def close(self):
        with self.lock:
            for connection in self.available:
                try:
                    # we _force_close because this connection may still used by another process
                    connection._force_close()
                except Exception as e:
                    logging.debug(f"unable to close database connection: {e}")

            for connection in self.in_use:
                try:
                    # we _force_close because this connection may still used by another process
                    connection._force_close()
                except Exception as e:
                    logging.debug(f"unable to close database connection: {e}")

            self.available.clear()
            self.in_use.clear()
            self.emit_monitors()

    def get_connection(self):
        connection = None
        with self.lock:
            try:
                connection = self.available.pop()

                # 8/5/2022 
                # make sure the connection is good before we move forward

                try:
                    connection.rollback()
                except Exception as e:
                    # if we can't rollback then toss this connection and get a new one
                    logging.warning(f"unable to rollback connection on get_connection: {e}")
                    self.close_connection(connection)
                    connection = self.open_new_connection()

                # drop old connections
                if datetime.now() >= connection.termination_date: # termination_date is a property we add in open_new_connection()
                    logging.info(f"terminating old connection {connection}")
                    self.close_connection(connection)
                    connection = self.open_new_connection()
            except IndexError:
                connection = self.open_new_connection()

            self.in_use.append(connection)
            connection.acquired = datetime.now()
            self.emit_monitors()

        return connection

    def return_connection(self, connection):
        if connection is None:
            return

        try:
            connection.rollback()
        except Exception as e:
            logging.warning(f"unable to rollback connection on return to pool: {e}")
            logging.warning(f"db connection ID: {connection}")
            self.destroy_connection(connection)
            return

        with self.lock:
            self.in_use.remove(connection)
            self.available.append(connection)
            self.emit_monitors()

    def close_connection(self, connection):
        try:
            connection.close()
        except Exception as e:
            logging.warning(f"unable to close database connection: {e} connection {connection}")

    def destroy_connection(self, connection):
        self.close_connection(connection)

        with self.lock:
            try:
                self.in_use.remove(connection)
                self.emit_monitors()
            except ValueError:
                logging.warning(f"attempted to remove missing database connection {connection}")

    def open_new_connection(self):
        connection = pymysql.connect(**self.kwargs)
        cursor = connection.cursor()
        cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
        cursor.close()
        connection.commit()

        # keep track of when this connection should be invalidated
        setattr(connection,
                'termination_date',
                datetime.now() + create_timedelta(get_config()['database']['max_connection_lifetime']))

        logging.debug(f"got new database connection to {self.name} ({len(self.in_use)} existing connections)")
        return connection

    def start(self):
        pass

    def stop(self):
        pass

    def clear(self):
        with self.lock:
            for c in self.available:
                try:
                    c.close()
                except Exception as e:
                    logging.error(f"unable to close database connection: {e}")

            self.available.clear()

            for c in self.in_use:
                try:
                    c.close()
                except Exception as e:
                    logging.error(f"unable to close database connection: {e}")

            self.in_use.clear()
            self.emit_monitors()

    @property
    def available_count(self):
        with self.lock:
            return len(self.available)

    @property
    def in_use_count(self):
        with self.lock:
            return len(self.in_use)

    def emit_monitors(self):
        emit_monitor(MONITOR_DB_POOL_AVAILABLE_COUNT, self.available_count)
        emit_monitor(MONITOR_DB_POOL_IN_USE_COUNT, self.in_use_count)

# the global queue of database connections available for use
_global_db_pools = {} # key = database name, value = _database_pool
_global_db_pools_lock = threading.RLock()

def get_pool(name='ace'):
    if name is None:
        name = 'ace'

    with _global_db_pools_lock:
        try:
            result = _global_db_pools[name]
        except KeyError:
            result =_global_db_pools[name] = _database_pool(name)
            logging.debug(f"created new pool {name}")

        # if the pool was created on another process then we just creat another pool to use
        # and ignore the old one (which may be used by the previous process)
        if result.pid != os.getpid():
            result.close() # closes the sockets without killing the database connections
            result = _global_db_pools[name] = _database_pool(name)
            logging.debug(f"created new pool {name} under pid {result.pid}")

        return result

def reset_pools():
    for name, pool in _global_db_pools.items():
        pool.clear()

    _global_db_pools.clear()

@contextmanager
def get_db_connection(name='ace'):
    if name is None:
        name = 'ace'

    connection = None
    try:
        connection = get_pool(name).get_connection()
        yield connection
    finally:
        get_pool(name).return_connection(connection)

def execute_with_db_cursor(db_name: str, target: Callable, *args, **kwargs):
    """Execute the given target function with a database connection and cursor.
    The target is called with any additional parameters passed in."""
    with get_db_connection(name=db_name) as db:
        cursor = db.cursor()
        return target(db, cursor, *args, **kwargs)

def initialize_database():
    """Initializes database connections by creating the SQLAlchemy engine and session objects."""

    global DatabaseSession
    from flask_config import get_flask_config

    # see https://github.com/PyMySQL/PyMySQL/issues/644
    # /usr/local/lib/python3.6/dist-packages/pymysql/cursors.py:170: Warning: (1300, "Invalid utf8mb4 character string: '800363'")
    warnings.filterwarnings(action='ignore', message='.*Invalid utf8mb4 character string.*')

    if get_db() is None:
        engine = create_engine(
            get_flask_config(get_config()['global']['instance_type']).SQLALCHEMY_DATABASE_URI, 
            isolation_level='READ COMMITTED',
            **get_flask_config(get_config()['global']['instance_type']).SQLALCHEMY_DATABASE_OPTIONS)

        @event.listens_for(engine, 'connect')
        def connect(dbapi_connection, connection_record):
            pid = os.getpid()
            connection_record.info['pid'] = pid

        @event.listens_for(engine, 'checkin')
        def checkin(dbapi_connection, connection_record):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, engine.pool.status())

        @event.listens_for(engine, 'checkout')
        def checkout(dbapi_connection, connection_record, connection_proxy):
            emit_monitor(MONITOR_SQLALCHEMY_DB_POOL_STATUS, engine.pool.status())

            pid = os.getpid()
            if connection_record.info['pid'] != pid:
                connection_record.dbapi_connection = connection_proxy.dbapi_connection = None
                message = f"connection record belongs to pid {connection_record.info['pid']} attempting to check out in pid {pid}"
                logging.debug(message)
                raise DisconnectionError(message)

        DatabaseSession = scoped_session(sessionmaker(bind=engine))

    else:
        # if you call this a second time it just closes all the sessions
        # this (currently) happens in unit testing
        from sqlalchemy.orm.session import close_all_sessions
        close_all_sessions()
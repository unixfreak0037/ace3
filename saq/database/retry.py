import functools
import logging
import random
import sys
import time

import pymysql
from sqlalchemy import Executable
from sqlalchemy.exc import DBAPIError
from saq.configuration.config import get_config_value_as_boolean
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_LOG_SQL
from saq.database.pool import get_db
from saq.error import report_exception


def execute_with_retry(db, cursor, sql_or_func, params=(), attempts=15, commit=False):
    """Executes the given SQL or function (and params) against the given cursor with
       re-attempts up to N times (defaults to 2) on deadlock detection.

       If sql_or_func is a callable then the function will be called as 
       sql_or_func(db, cursor, *params).
       
       To execute a single statement, sql is the parameterized SQL statement
       and params is the tuple of parameter values.  params is optional and defaults
       to an empty tuple.
    
       To execute multi-statement transactions, sql is a list of parameterized
       SQL statements, and params is a matching list of tuples of parameters.
       
       Returns the rowcount for a single statement, or a list of rowcount for multiple statements,
       or the result of the function call."""

    assert callable(sql_or_func) or isinstance(sql_or_func, str) or isinstance(sql_or_func, list)
    assert params is None or isinstance(params, tuple) or ( 
        isinstance(params, list) and all([isinstance(_, tuple) for _ in params]) )

    # if we are executing sql then make sure we have a list of SQL statements and a matching list
    # of tuple parameters
    if not callable(sql_or_func):
        if isinstance(sql_or_func, str):
            sql_or_func = [ sql_or_func ]

        if isinstance(params, tuple):
            params = [ params ]
        elif params is None:
            params = [ () for _ in sql_or_func ]

        if len(sql_or_func) != len(params):
            raise ValueError("the length of sql statements does not match the length of parameter tuples: {} {}".format(
                             sql_or_func, params))
    count = 1
    while True:
        try:
            results = []
            if callable(sql_or_func):
                results.append(sql_or_func(db, cursor, *params))
            else:
                for (_sql, _params) in zip(sql_or_func, params):
                    if get_config_value_as_boolean(CONFIG_GLOBAL, CONFIG_GLOBAL_LOG_SQL):
                        logging.debug(f"executing with retry (attempt #{count}) sql {_sql} with paramters {_params}")
                    cursor.execute(_sql, _params)
                    results.append(cursor.rowcount)

            if commit:
                db.commit()

            if len(results) == 1:
                return results[0]
            
            return results

        except pymysql.err.OperationalError as e:
            # see http://stackoverflow.com/questions/25026244/how-to-get-the-mysql-type-of-error-with-pymysql
            # to explain e.args[0]
            if (e.args[0] == 1213 or e.args[0] == 1205) and count < attempts:
                logging.warning("deadlock detected -- trying again (attempt #{})".format(count))
                try:
                    db.rollback()
                except Exception as rollback_error:
                    logging.error("rollback failed for transaction in deadlock: {}".format(rollback_error))
                    raise e

                count += 1
                time.sleep(random.uniform(0, 1))
                continue
            else:
                if not callable(sql_or_func):
                    i = 0
                    for _sql, _params in zip(sql_or_func, params):
                        logging.warning("DEADLOCK STATEMENT #{} SQL {} PARAMS {}".format(i, _sql, ','.join([str(_) for _ in _params])))
                        i += 1

                    # TODO log innodb lock status
                    raise e

def retry_on_deadlock(targets, *args, attempts=15, commit=False, **kwargs):
    """Executes the given targets, in order. If a deadlock condition is detected, the database session
       is rolled back and the targets are executed in order, again. This can happen up to :param:attempts times
       before the failure is raised as an exception.

       :param targets Can be any of the following
       * A callable.
       * A list of callables.
       * A sqlalchemy.sql.expression.Executable object.
       * A list of sqlalchemy.sql.expression.Executable objects.
       :param int attempts The maximum number of times the operations are tried before passing the exception on.
       :param bool commit If set to True then the ``commit`` function is called on the session object before returning
       from the function. If a deadlock occurs during the commit then further attempts are made.

       In the case where targets are functions, session can be omitted, in which case :meth:get_db() is used to 
       acquire a Session to use. When this is the case, the acquired Session object is passed as a keyword parameter
       to the functions.

       In the case where targets are executables, session cannot be omitted. The executables are passed to the
       ``execute`` function of the Session object as if you had called ``session.execute(target)``.

       :return This function returns the last operation in the list of targets."""

    if not isinstance(targets, list):
        targets = [ targets ]

    current_attempt = 0
    while True:
        try:
            last_result = None
            for target in targets:
                if isinstance(target, Executable) or isinstance(target, str):
                    get_db().execute(target, *args, **kwargs)
                elif callable(target):
                    last_result = target(*args, **kwargs)

            if commit:
                get_db().commit()

            return last_result

        except DBAPIError as e:
            # catch the deadlock error ids 1213 and 1205
            # NOTE this is for MySQL only
            if e.orig.args[0] == 1213 or e.orig.args[0] == 1205 and current_attempt < attempts:
                logging.debug(f"DEADLOCK STATEMENT attempt #{current_attempt + 1} SQL {e.statement} PARAMS {e.params}")

                try:
                    get_db().rollback() # rolls back to the begin_nested()
                except Exception as e:
                    logging.error(f"unable to roll back transaction: {e}")
                    report_exception()

                    et, ei, tb = sys.exc_info()
                    raise e.with_traceback(tb)

                # ... and try again 
                time.sleep(0.1) # ... after a bit
                current_attempt += 1
                continue

            # otherwise we propagate the error
            et, ei, tb = sys.exc_info()
            raise e.with_traceback(tb)

def retry_function_on_deadlock(function, *args, **kwargs):
    assert callable(function)
    return retry_on_deadlock(function, *args, **kwargs)

def retry_sql_on_deadlock(executable, *args, **kwargs):
    assert isinstance(executable, Executable)
    return retry_on_deadlock(executable, *args, **kwargs)

def retry_multi_sql_on_deadlock(executables, *args, **kwargs):
    assert isinstance(executables, list)
    assert all([isinstance(_, Executable) for _ in executables])
    return retry_on_deadlock(executables, *args, **kwargs)

def retry(func, *args, **kwargs):
    """Executes the wrapped function with retry_on_deadlock."""
    @functools.wraps(func)
    def wrapper(*w_args, **w_kwargs):
        w_kwargs.update(kwargs)
        return retry_function_on_deadlock(func, *w_args, **w_kwargs)

    return wrapper
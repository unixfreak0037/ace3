import logging
import time

from saq.configuration.config import get_config_value_as_boolean
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_LOG_SQL_EXEC_TIMES

from sqlalchemy import event
from sqlalchemy.engine import Engine

@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if get_config_value_as_boolean(CONFIG_GLOBAL, CONFIG_GLOBAL_LOG_SQL_EXEC_TIMES):
        context._query_start_time = time.time()
        logging.debug("START QUERY {} ({})".format(statement, parameters))
    # Modification for StackOverflow answer:
    # Show parameters, which might be too verbose, depending on usage..
    #logging.debug("Parameters:\n%r" % (parameters,))

@event.listens_for(Engine, "after_cursor_execute")
def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    if get_config_value_as_boolean(CONFIG_GLOBAL, CONFIG_GLOBAL_LOG_SQL_EXEC_TIMES):
        total = time.time() - context._query_start_time
        logging.debug("END QUERY {:02f} {} ({})".format(total * 1000, statement, parameters))

    # Modification for StackOverflow: times in milliseconds
    #logger.debug("Total Time: %.02fms" % (total*1000))
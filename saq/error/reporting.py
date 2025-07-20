from datetime import datetime
import logging
import os
import shutil
import sys
import traceback
from typing import TYPE_CHECKING, Optional

from saq.configuration.config import get_config_value, get_config_value_as_boolean
from saq.constants import CONFIG_ENGINE, CONFIG_ENGINE_COPY_ANALYSIS_ON_ERROR, CONFIG_GLOBAL, CONFIG_GLOBAL_ERROR_REPORTING_DIR, G_DUMP_TRACEBACKS
if TYPE_CHECKING:
    from saq.engine.execution_context import EngineExecutionContext
from saq.environment import g_boolean, get_data_dir


def report_exception(execution_context: Optional["EngineExecutionContext"]=None):

    exc_type, reported_exception, tb = sys.exc_info()

    # spit it out to stdout first
    if g_boolean(G_DUMP_TRACEBACKS):
        traceback.print_exc()

    try:
        output_dir = os.path.join(get_data_dir(), get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_ERROR_REPORTING_DIR, default="error_reports"))
        error_report_path = os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f'))
        with open(error_report_path, 'w') as fp:
            if execution_context:
                fp.write("CURRENT ANALYSIS TARGET: {}\n".format(execution_context.root))
                if execution_context.root:
                    fp.write("CURRENT ANALYSIS MODE: {}\n".format(execution_context.root.analysis_mode))

            fp.write("EXCEPTION\n")
            fp.write(str(reported_exception))
            fp.write("\n\nSTACK TRACE\n")

            from saq.error.formatter import ExceptionFormatter
            formatter = ExceptionFormatter()
            stack_trace, final_source = formatter.format_traceback(tb)

            fp.write(stack_trace)
            fp.write("\n\nEXCEPTION SOURCE\n")
            fp.write(final_source)
            fp.write("\n")

        if get_config_value_as_boolean(CONFIG_ENGINE, CONFIG_ENGINE_COPY_ANALYSIS_ON_ERROR):
            if execution_context:
                if os.path.isdir(execution_context.root.storage_dir):
                    analysis_dir = '{}.ace'.format(error_report_path)
                    try:
                        shutil.copytree(execution_context.root.storage_dir, analysis_dir)
                        logging.warning("copied analysis from {} to {} for review".format(execution_context.root.storage_dir, analysis_dir))
                    except Exception as e:
                        logging.error("unable to copy from {} to {}: {}".format(execution_context.root.storage_dir, analysis_dir, e))

        return error_report_path

    except Exception as e:
        logging.error("uncaught exception we reporting an exception: {}".format(e))
        return None
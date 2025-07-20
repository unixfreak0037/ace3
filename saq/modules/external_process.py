import logging
import os
import signal
from saq.modules.base_module import AnalysisModule


class ExternalProcessAnalysisModule(AnalysisModule):
    """An analysis module that executes an external process as part of it's analysis."""
    
    def __init__(self, *args, **kwargs):
        super(ExternalProcessAnalysisModule, self).__init__(*args, **kwargs)
        
        # reference to the Popen command result
        self.external_process = None

    def handle_cancel_event(self):
        # kill the external process
        if self.external_process is not None:
            logging.debug("terminating external process {0}".format(self.external_process))
            try:
                os.killpg(self.external_process.pid, signal.SIGTERM)
                self.external_process.wait(5)
            except:
                logging.debug("killing external process {0}".format(self.external_process))
                try:
                    os.killpg(self.external_process.pid, signal.SIGKILL)
                    self.external_process.wait()
                except Exception as e:
                    logging.debug("unable to kill external process {0}: {1}".format(self.external_process, str(e)))
                    #report_exception()
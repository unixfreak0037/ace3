# vim: sw=4:ts=4:et

import logging

from saq.configuration import get_config_value_as_boolean, get_config_value_as_list
from saq.constants import CONFIG_ENGINE, CONFIG_ENGINE_STOP_ANALYSIS_ON_ANY_ALERT_DISPOSITION, CONFIG_ENGINE_STOP_ANALYSIS_ON_DISPOSITIONS, DISPOSITION_OPEN, G_FORCED_ALERTS
from saq.database import get_db_connection
from saq.environment import g_boolean
from saq.modules import AnalysisModule
from saq.modules.base_module import AnalysisExecutionResult

class ACEAlertDispositionAnalyzer(AnalysisModule):
    """Cancels any further analysis if the disposition has been set by the analyst."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_mode = self.config['target_mode']

    def execute_pre_analysis(self):
        self.check_disposition()

    def execute_threaded(self):
        self.check_disposition()

    def check_disposition(self):
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("SELECT disposition FROM alerts WHERE uuid = %s", (self.get_root().uuid,))
            row = c.fetchone()
            # did the alert vanish from the database?
            if row is None:
                logging.warning("alert {} seems to have vanished from the database".format(self.get_root().uuid))
                self.get_engine().cancel_analysis()

            # Get the two different stop analysis setting values
            stop_analysis_on_any_alert_disposition = get_config_value_as_boolean(CONFIG_ENGINE, CONFIG_ENGINE_STOP_ANALYSIS_ON_ANY_ALERT_DISPOSITION, default=False)
            stop_analysis_on_dispositions = get_config_value_as_list(CONFIG_ENGINE, CONFIG_ENGINE_STOP_ANALYSIS_ON_DISPOSITIONS, default=[])

            # Check to see if we need to stop analysis based on the settings
            disposition = row[0]
            if stop_analysis_on_any_alert_disposition and disposition != DISPOSITION_OPEN:
                logging.info("alert {} has been dispositioned - canceling analysis".format(self.get_root().uuid))
                self.get_engine().cancel_analysis()
            elif disposition in stop_analysis_on_dispositions:
                logging.info("alert {} has been dispositioned as {} - canceling analysis".format(self.get_root().uuid, disposition))
                self.get_engine().cancel_analysis()
            elif disposition:
                logging.info(f"alert {self.get_root()} dispositioned as {disposition} but continuing analysis")

class ACEDetectionAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_mode = self.config['target_mode']

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        # do not alert on a root that has been whitelisted
        if not g_boolean(G_FORCED_ALERTS) and self.get_root().whitelisted:
            logging.debug("{} has been whitelisted".format(self.get_root()))
            return AnalysisExecutionResult.COMPLETED

        if g_boolean(G_FORCED_ALERTS) or self.get_root().has_detections():
            logging.info("{} has {} detection points - changing mode to {}".format(
                         self.get_root(), len(self.get_root().all_detection_points), self.target_mode))
            self.get_root().analysis_mode = self.target_mode

        return AnalysisExecutionResult.COMPLETED

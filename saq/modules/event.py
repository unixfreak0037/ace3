import logging

from saq.analysis import Analysis
from saq.constants import ANALYSIS_MODE_EVENT, AnalysisExecutionResult
from saq.database import Alert, EventMapping, get_db
from saq.modules import AnalysisModule

# TODO trash this

class AlertAddedToEventAnalysis(Analysis):
    pass

class AlertAddedToEventAnalyzer(AnalysisModule):
    """Changes the analysis mode to event if the alert has been added to an event"""

    @property
    def generated_analysis_type(self):
        return AlertAddedToEventAnalysis

    def execute_analysis(self, target) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.COMPLETED

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        # this will return 1 result or None, use this instead of .one_or_none b/c that will raise an Exception
        # if the alert has been added to multiple events
        event_mapping = get_db().query(EventMapping)\
            .join(Alert, EventMapping.alert_id == Alert.id)\
            .filter(Alert.uuid == self.get_root().uuid).first()

        if event_mapping:
            logging.info(f'AlertAddedToEvent setting analysis mode to {ANALYSIS_MODE_EVENT} for {self.get_root().uuid}')
            self.get_root().analysis_mode = ANALYSIS_MODE_EVENT

        return AnalysisExecutionResult.COMPLETED

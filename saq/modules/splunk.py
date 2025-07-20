# vim: sw=4:ts=4:et:cc=120

from datetime import datetime

import pytz

from saq.configuration import get_config_value
from saq.constants import CONFIG_SPLUNK_TIMEZONE
from saq.modules.api_analysis import BaseAPIAnalysis, BaseAPIAnalyzer, AnalysisDelay
from saq.splunk import extract_event_timestamp, SplunkClient
from saq.util import format_iso8601, parse_event_time


#
# Requirements for Splunk queries
#
# <O_VALUE> is replaced by the value of the observable
# <O_TYPE> is replaced by the type of the observable
# <O_TIMESPEC> is replaced by the formatted timerange (done all in one to allow searching by index time)
#

class SplunkAPIAnalysis(BaseAPIAnalysis):
    @property
    def search_id(self):
        return self.details.get('search_id', None)

    @search_id.setter
    def search_id(self, value):
        self.details['search_id'] = value

    @property
    def dispatch_state(self):
        return self.details.get('dispatch_state', None)

    @dispatch_state.setter
    def dispatch_state(self, value):
        self.details['dispatch_state'] = value

    @property
    def start_time(self):
        result = self.details.get('start_time', None)
        if result is None:
            return None

        return parse_event_time(result)

    @start_time.setter
    def start_time(self, value):
        if isinstance(value, datetime):
            value = format_iso8601(value)

        self.details['start_time'] = value

    @property
    def running_start_time(self):
        result = self.details.get('running_start_time', None)
        if result is None:
            return None

        return parse_event_time(result)

    @running_start_time.setter
    def running_start_time(self, value):
        if isinstance(value, datetime):
            value = format_iso8601(value)

        self.details['running_start_time'] = value

    @property
    def end_time(self):
        result = self.details.get('end_time', None)
        if result is None:
            return None

        return parse_event_time(result)

    @end_time.setter
    def end_time(self, value):
        if isinstance(value, datetime):
            value = format_iso8601(value)

        self.details['end_time'] = value


class SplunkAPIAnalyzer(BaseAPIAnalyzer):
    """Base Module to make AnalysisModule performing correlational Splunk queries.

          This class should be overridden for each individual Splunk query.

          Attributes (in addition to parent class attrs):
              timezone: str that contains configured timezone for Splunk API instance (ex. GMT)
              use_index_time: bool that contains whether a query should search based on index time
              namespace_app: str that contains namespace_app, if necessary
              namespace_user: str that contains namespace_user, if necessary
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.timezone = get_config_value(self.api, CONFIG_SPLUNK_TIMEZONE)
        self.use_index_time = self.config.getboolean('use_index_time')

        self.splunk = SplunkClient(
            self.api,
            user_context = self.config.get('splunk_user_context'),
            app = self.config.get('splunk_app_context'),
        )

    @property
    def generated_analysis_type(self):
        return SplunkAPIAnalysis

    def search_url(self, query=None) -> str:
        """Returns the url encoded search link. If you do not specify the query parameter, it defaults to use the
        self.target_query. Being able to customize the query can help in cases where the query might have something like
        a "| stats count" in it, but you want to link the user to a query that will give them the actual results."""
        if query is None:
            query = self.target_query

        return self.splunk.encoded_query_link(query)

    def _escape_value(self, value: str) -> str:
        # Make sure any backslashes are escaped first
        value = value.replace('\\', '\\\\')
        return value.replace('"', '\\"').replace("'", "\\'")

    def fill_target_query_timespec(self, start_time, stop_time):
        tz = pytz.timezone(self.timezone)

        earliest = start_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')
        latest = stop_time.astimezone(tz).strftime('%m/%d/%Y:%H:%M:%S')

        if self.use_index_time:
            time_spec = f'_index_earliest = {earliest} _index_latest = {latest}'
        else:
            time_spec = f'earliest = {earliest} latest = {latest}'

        # set the gui link
        self.analysis.details['gui_link'] = self.splunk.encoded_query_link(
            self.target_query.replace('<O_TIMESPEC>', ''),
            start_time.astimezone(tz),
            stop_time.astimezone(tz),
        )

        self.target_query = self.target_query.replace('<O_TIMESPEC>', time_spec)

    # Based on QRadarAPIAnalysis, but may not need this in the future
    def process_splunk_event(self, analysis, observable, event, event_time):
        """Called for each event processed by the module. Can be overridden by subclasses."""
        pass

    def process_query_results(self, query_results, analysis, observable):
        for event in query_results:
            event_time = extract_event_timestamp(event)
            self.process_splunk_event(analysis, observable, event, event_time)
            self.extract_result_observables(analysis, event, observable, event_time)

    def execute_query(self):
        # execute the query
        self.splunk.reset_search_status(
            dispatch_state=self.analysis.dispatch_state,
            start_time=self.analysis.start_time,
            running_start_time=self.analysis.running_start_time,
            end_time=self.analysis.end_time)

        self.analysis.search_id, results = self.splunk.query_async(self.target_query, self.analysis.search_id, limit=self.max_result_count)

        self.analysis.dispatch_state = self.splunk.dispatch_state
        self.analysis.start_time = self.splunk.start_time
        self.analysis.running_start_time = self.splunk.running_start_time
        self.analysis.end_time = self.splunk.end_time

        # delay if there are no results
        if results is None:
            raise AnalysisDelay()

        # return results
        return results



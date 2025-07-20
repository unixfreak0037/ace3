import datetime
import pytest

from saq.configuration import get_config
from saq.constants import F_EMAIL_SUBJECT
from saq.splunk import SplunkQueryObject
from saq.analysis import RootAnalysis
from saq.modules.api_analysis import AnalysisDelay
from saq.modules.splunk import SplunkAPIAnalyzer, SplunkAPIAnalysis
from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.mock_datetime import MOCK_NOW

class MockSplunk(SplunkQueryObject):
    def encoded_query_link(self, query):
        return query + ' world'

    def query_async(self, query, search_id=None, limit=1000):
        return search_id + 1, query


@pytest.mark.unit
def test_splunk_api_analyzer_search_url(monkeypatch, test_context):
    #mock
    monkeypatch.setattr("saq.splunk.SplunkQueryObject", MockSplunk)

    # init analyzer
    analyzer = SplunkAPIAnalyzer(context=test_context)
    analyzer.target_query = 'hello'

    # test no param
    result = analyzer.search_url()
    assert result == 'hello world'

    # test with param
    result = analyzer.search_url('foo')
    assert result == 'foo world'


@pytest.mark.unit
def test_splunk_api_analyzer_execute_query(monkeypatch, test_context):
    #mock
    monkeypatch.setattr("saq.splunk.SplunkQueryObject", MockSplunk)

    # init
    analyzer = SplunkAPIAnalyzer(context=test_context)
    analyzer.target_query = 'hello'
    analyzer.analysis = SplunkAPIAnalysis()
    analyzer.analysis.search_id = 0

    # test completed query
    result = analyzer.execute_query()
    assert result == 'hello'
    assert analyzer.analysis.search_id == 1

    # test delay
    analyzer.target_query = None
    with pytest.raises(AnalysisDelay):
        result = analyzer.execute_query()


@pytest.mark.unit
def test_splunk_api_analyzer_fill_timespec(test_context):
    # init
    analyzer = SplunkAPIAnalyzer(context=test_context)
    analyzer.target_query = 'hello <O_TIMESPEC> world'
    analyzer.analysis = SplunkAPIAnalysis()

    # test fill timespec
    analyzer.fill_target_query_timespec(MOCK_NOW, MOCK_NOW)

    # verify
    assert analyzer.target_query == 'hello _index_earliest = 11/11/2017:07:36:01 _index_latest = 11/11/2017:07:36:01 world'
    assert analyzer.analysis.details['gui_link'] == 'https://www.test.com/en-US/app/search/search?q=search+hello++world&earliest=1510385761&latest=1510385761'


@pytest.mark.unit
def test_splunk_api_analyzer_escape_value(test_context):

    observable = RootAnalysis().add_observable_by_spec(F_EMAIL_SUBJECT, 'Hello, "World"')
    analyzer = SplunkAPIAnalyzer(context=test_context)
    analyzer.target_query_base = '<O_VALUE>'
    analyzer.analysis = SplunkAPIAnalysis()
    analyzer.build_target_query(observable, source_event_time=datetime.datetime.now())

    assert analyzer.target_query == 'Hello, \\"World\\"'

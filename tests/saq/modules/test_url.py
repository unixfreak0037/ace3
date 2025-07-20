import http
import os
import socketserver
import threading
import pytest

from saq.analysis.root import load_root
from saq.configuration.config import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_TYPE_MANUAL, DIRECTIVE_CRAWL, DIRECTIVE_EXTRACT_URLS, F_FILE, F_URL, G_ANALYST_DATA_DIR, R_DOWNLOADED_FROM
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.environment import g
from saq.modules.url.crawlphish import CrawlphishAnalysisV2, CrawlphishAnalyzer
from tests.saq.helpers import create_root_analysis, log_count

LOCAL_PORT = 43124
    
@pytest.fixture(autouse=True, scope="function")
def setup():
    # disable proxy for crawlphish
    get_config()['proxy']['transport'] = ''
    get_config()['proxy']['host'] = ''
    get_config()['proxy']['port'] = ''
    get_config()['proxy']['user'] = ''
    get_config()['proxy']['password'] = ''

@pytest.fixture
def custom_tcp_server():

    class _customTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    web_server = _customTCPServer(('', LOCAL_PORT), http.server.SimpleHTTPRequestHandler)
    web_server_thread = threading.Thread(target=web_server.serve_forever)
    web_server_thread.daemon = True
    web_server_thread.start()

    yield

    web_server.shutdown()

@pytest.mark.integration
def test_url_download_conditions_no_directive(root_analysis):

    root_analysis.analysis_mode = "test_groups"
    url = root_analysis.add_observable_by_spec(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_crawlphish', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(root_analysis.storage_dir)
    
    url = root_analysis.get_observable(url.id)
    analysis = url.get_and_load_analysis(CrawlphishAnalysisV2)
    assert not analysis

@pytest.mark.integration
def test_url_download_conditions_with_directive(root_analysis):

    root_analysis.analysis_mode = "test_groups"
    url = root_analysis.add_observable_by_spec(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
    url.add_directive(DIRECTIVE_CRAWL)
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_crawlphish', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(root_analysis.storage_dir)

    url = root_analysis.get_observable(url.id)
    analysis = url.get_and_load_analysis(CrawlphishAnalysisV2)
    assert isinstance(analysis, CrawlphishAnalysisV2)

@pytest.mark.integration
def test_url_download_conditions_manual_alert(root_analysis):

    root_analysis.analysis_mode = "test_groups"
    root_analysis.alert_type = ANALYSIS_TYPE_MANUAL
    url = root_analysis.add_observable_by_spec(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_crawlphish', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(root_analysis.storage_dir)

    url = root_analysis.get_observable(url.id)
    analysis = url.get_and_load_analysis(CrawlphishAnalysisV2)
    assert isinstance(analysis, CrawlphishAnalysisV2)

@pytest.mark.integration
def test_url_download_conditions_auto_crawl(root_analysis):

    get_config()['analysis_module_crawlphish']['auto_crawl_all_alert_urls'] = 'yes'
    root_analysis.analysis_mode = "test_groups"
    root_analysis.analysis_mode = ANALYSIS_MODE_CORRELATION
    url = root_analysis.add_observable_by_spec(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine(config=EngineConfiguration(local_analysis_modes=[ANALYSIS_MODE_CORRELATION]))
    engine.configuration_manager.enable_module('analysis_module_crawlphish', 'correlation')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(root_analysis.storage_dir)

    url = root_analysis.get_observable(url.id)
    analysis = url.get_and_load_analysis(CrawlphishAnalysisV2)
    assert isinstance(analysis, CrawlphishAnalysisV2)

@pytest.mark.skip(reason="These tests with the TCP server sometimes fail because they are already listening.")
@pytest.mark.system
def test_basic_download(custom_tcp_server, root_analysis):

    root_analysis.analysis_mode = "test_groups"
    url = root_analysis.add_observable_by_spec(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
    url.add_directive(DIRECTIVE_CRAWL)
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_crawlphish', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(root_analysis.storage_dir)

    url = root_analysis.get_observable(url.id)
    analysis = url.get_and_load_analysis(CrawlphishAnalysisV2)

    assert analysis.status_code == 200
    assert analysis.file_name == 'crawlphish.000'
    assert analysis.downloaded
    assert analysis.error_reason is None

    # there should be a single F_FILE observable
    file_observables = analysis.get_observables_by_type(F_FILE)
    assert len(file_observables) == 1
    file_observable = file_observables[0]

    assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert file_observable.has_relationship(R_DOWNLOADED_FROM)

@pytest.mark.skip(reason="These tests with the TCP server sometimes fail because they are already listening.")
@pytest.mark.system
def test_download_multiple_uas_duplicate_content(custom_tcp_server, root_analysis):

    # tests the case where we are multiple multiple user agent strings
    # and each request returns the same data

    get_config()['analysis_module_crawlphish']['user_agent_list_path'] = "test_uas.txt"

    target_path = os.path.join(g(G_ANALYST_DATA_DIR), "test_uas.txt")
    with open(target_path, 'w') as fp:
        fp.write("user-agent-1\nuser-agent-2\n")

    root_analysis.analysis_mode = "test_groups"
    url = root_analysis.add_observable_by_spec(F_URL, 'http://localhost:{}/test_data/crawlphish.000'.format(LOCAL_PORT))
    url.add_directive(DIRECTIVE_CRAWL)
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_crawlphish', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(root_analysis.storage_dir)

    url = root_analysis.get_observable(url.id)
    analysis = url.get_and_load_analysis(CrawlphishAnalysisV2)

    assert analysis.status_code == 200
    assert analysis.file_name, 'crawlphish.000'
    assert analysis.downloaded
    assert analysis.error_reason is None

    # we should see a log message about having already downloaded the same file
    assert log_count("already downloaded d9014c4624844aa5bac314773d6b689ad467fa4e1d1a50a1b8a99d5a95f72ff5") == 1

    # there should be a single F_FILE observable
    # even though we requested it twice, we should only see a single file
    file_observables = analysis.get_observables_by_type(F_FILE)
    assert len(file_observables) == 1
    file_observable = file_observables[0]

    assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert file_observable.has_relationship(R_DOWNLOADED_FROM)

    # there should be some extra content added to the details
    assert 'user-agent-1' in analysis.details['extended_information']['GLOBAL']

@pytest.mark.skip(reason="These tests with the TCP server sometimes fail because they are already listening.")
@pytest.mark.system
def test_download_404(custom_tcp_server, root_analysis):
    """We should download even if we get an error results back."""

    root_analysis.analysis_mode = "test_groups"
    url = root_analysis.add_observable_by_spec(F_URL, 'http://localhost:{}/test_data/crawlphish.001'.format(LOCAL_PORT))
    url.add_directive(DIRECTIVE_CRAWL)
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('analysis_module_crawlphish', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(root_analysis.storage_dir)

    url = root_analysis.get_observable(url.id)
    analysis = url.get_and_load_analysis(CrawlphishAnalysisV2)

    assert analysis.proxy_results['GLOBAL'].status_code == 404
    if 'tor' in analysis.proxy_results:
        assert analysis.proxy_results['tor'].status_code is None
    assert analysis.file_name == 'crawlphish.001'
    assert analysis.downloaded
    assert analysis.error_reason is None
    
    file_observables = analysis.get_observables_by_type(F_FILE)
    assert len(file_observables) == 1
    file_observable = file_observables[0]

    assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)
    assert file_observable.has_relationship(R_DOWNLOADED_FROM)

@pytest.mark.unit
def test_load_user_agent_list_file(monkeypatch, test_context):
    ua_file_path = os.path.join(g(G_ANALYST_DATA_DIR), 'test_uas.txt')
    with open(ua_file_path, 'w') as fp:
        fp.write("test-ua-1\ntest-ua-2\n")

    try:
        monkeypatch.setitem(get_config()['analysis_module_crawlphish'], 'user_agent_list_path', 'test_uas.txt')
        analyzer = CrawlphishAnalyzer(context=test_context)
        analyzer.load_user_agent_list()
        assert analyzer.user_agent_list == [ "test-ua-1", "test-ua-2" ]
    finally:
        os.remove(ua_file_path)

@pytest.mark.unit
def test_load_user_agent_list_file_with_comments(monkeypatch, test_context):
    ua_file_path = os.path.join(g(G_ANALYST_DATA_DIR), 'test_uas.txt')
    with open(ua_file_path, 'w') as fp:
        fp.write("test-ua-1\n# this is a comment\ntest-ua-2\n")

    try:
        monkeypatch.setitem(get_config()['analysis_module_crawlphish'], 'user_agent_list_path', 'test_uas.txt')
        analyzer = CrawlphishAnalyzer(context=test_context)
        analyzer.load_user_agent_list()
        assert analyzer.user_agent_list == [ "test-ua-1", "test-ua-2" ]
    finally:
        os.remove(ua_file_path)

@pytest.mark.unit
def test_missing_user_agent_list_file(monkeypatch, test_context):
    monkeypatch.setitem(get_config()['analysis_module_crawlphish'], 'user_agent_list_path', 'missing_file.txt')
    monkeypatch.setitem(get_config()['analysis_module_crawlphish'], 'user-agent', 'test ua')
    analyzer = CrawlphishAnalyzer(context=test_context)
    analyzer.load_user_agent_list()
    assert analyzer.user_agent_list == [ "test ua" ]



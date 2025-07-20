import pytest
import json
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from tests.saq.requests import site_mock
from saq.requests_wrapper import Session, Range

def get_mock_request(status_code, response_text=''):
    class MockResponse():
        def __init__(self, status_code, request):
            self.status_code = status_code
            self.request = request
            self.content = response_text.encode('utf-8')

        def raise_for_status(self):
            if 400 <= self.status_code < 600:
                raise Exception('status')

        def json(self, **kwargs):
            return json.loads(response_text)

    def mock_request(self, method, url, **kwargs):
        request = {
            'method': method,
            'url': url,
            'timeout': kwargs['timeout'],
            'https': self.adapters['https://'],
            'http': self.adapters['http://'],
        }
        return MockResponse(status_code, request)

    return mock_request


@pytest.mark.unit
def test_range():
    r = Range(1, 10, [3])
    assert 0 not in r
    assert 1 in r
    assert 2 in r
    assert 3 not in r
    assert 4 in r
    assert 5 in r
    assert 6 in r
    assert 7 in r
    assert 8 in r
    assert 9 in r
    assert 10 not in r


@pytest.mark.unit
def test_session(monkeypatch):
    # mock
    mock_request = get_mock_request(200)
    monkeypatch.setattr("saq.requests_wrapper.requests.Session.request", mock_request)

    # run
    session = Session('https://www.google.com', 1, 2, 3, [501])
    response = session.get('/url')

    # verify
    assert response.request['method'] == 'GET'
    assert response.request['url'] == 'https://www.google.com/url'
    assert response.request['timeout'] == 1
    assert response.request['https'] == response.request['http']
    assert isinstance(response.request['https'], HTTPAdapter)
    assert isinstance(response.request['https'].max_retries, Retry)
    assert response.request['https'].max_retries.total == 2
    assert response.request['https'].max_retries.status_forcelist.minimum == 400
    assert response.request['https'].max_retries.status_forcelist.maximum == 600
    assert response.request['https'].max_retries.status_forcelist.exclude == [501]
    assert response.request['https'].max_retries.backoff_factor == 3
    assert not response.request['https'].max_retries.raise_on_status


@pytest.mark.unit
def test_session_override(monkeypatch):
    # mock
    mock_request = get_mock_request(200)
    monkeypatch.setattr("saq.requests_wrapper.requests.Session.request", mock_request)

    # run
    session = Session('https://www.google.com', 1, 2, 3, [501])
    response = session.get('/url', timeout=10, max_retries=20, backoff_factor=30, halt_statuses=[502])

    # verify
    assert response.request['method'] == 'GET'
    assert response.request['url'] == 'https://www.google.com/url'
    assert response.request['timeout'] == 10
    assert response.request['https'] == response.request['http']
    assert isinstance(response.request['https'], HTTPAdapter)
    assert isinstance(response.request['https'].max_retries, Retry)
    assert response.request['https'].max_retries.total == 20
    assert response.request['https'].max_retries.status_forcelist.minimum == 400
    assert response.request['https'].max_retries.status_forcelist.maximum == 600
    assert response.request['https'].max_retries.status_forcelist.exclude == [501, 502]
    assert response.request['https'].max_retries.backoff_factor == 30
    assert not response.request['https'].max_retries.raise_on_status


@pytest.mark.unit
def test_session_error(monkeypatch):
    # mock
    mock_request = get_mock_request(400)
    monkeypatch.setattr("saq.requests_wrapper.requests.Session.request", mock_request)

    # run
    session = Session()
    with pytest.raises(Exception) as e:
        session.get('https://www.google.com')


    # verify
    assert str(e.value) == 'status'


@pytest.mark.unit
def test_session_error_handler(monkeypatch):
    # mock
    mock_request = get_mock_request(400)
    monkeypatch.setattr("saq.requests_wrapper.requests.Session.request", mock_request)

    e = None
    def error_handler(response):
        nonlocal e
        e = response.status_code

    # run
    session = Session()
    session.error_handler = error_handler
    session.get('https://www.google.com')

    # verify
    assert e == 400

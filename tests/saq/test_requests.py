import pytest
from saq.requests_wrapper import Session
from requests import HTTPError
from tests.saq.requests import mock_site

@pytest.mark.unit
def test_exabeam_login(requests_mock):
    mock_site(requests_mock, None, [{
        'method': 'GET',
        'url': 'https://some-api/whatever/',
        'status_code': 401,
    }])

    session = Session(backoff_factor=0)
    with pytest.raises(HTTPError):
        r = session.get('https://some-api/whatever/')

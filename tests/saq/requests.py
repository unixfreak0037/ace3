import json
import os.path
import requests
from requests.models import RequestEncodingMixin
import urllib.parse as urlparse
from urllib.parse import urlencode
import pytest

def mock_proxies():
    return {}

class MockAuth(requests.auth.AuthBase):
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, request):
        return request

def create_validation_callback(request_text):
    def validate_request(request):
        if request_text is not None:
            assert request_text == request.text
        return True
    return validate_request

@pytest.fixture
def site_mock(requests_mock):
    def add(url, response='', status_code=200, method='GET', params=None, data=None, headers=None, response_headers=None, binary=False):
        if params:
            url_parts = list(urlparse.urlparse(url))
            url_parts[4] = RequestEncodingMixin._encode_params(params) 
            url = urlparse.urlunparse(url_parts)

        if headers is None:
            headers = {}

        if response_headers is None:
            response_headers = {}

        if not isinstance(response, str) and not callable(response):
            response = json.dumps(response)

        if data is not None and not isinstance(data, str) and not callable(data):
            data = json.dumps(data)

        def matcher(request, context):
            # verify headers
            for header in headers:
                assert request.headers[header] == headers[header]

            # verify data
            if data is not None:
                if callable(data):
                    data(request.text)
                else:
                    assert data == request.text

            # return response
            if callable(response):
                return response(request, context)
            return response

        if binary:
            requests_mock.register_uri(
                method,
                url,
                headers = response_headers,
                status_code = status_code,
                content = matcher,
            )
        else:
            requests_mock.register_uri(
                method,
                url,
                headers = response_headers,
                status_code = status_code,
                text = matcher,
            )

    return add
        

def mock_site(requests_mock, datadir, site_map):
    for site in site_map:
        url = site.get('url', 'https://localhost')
        if 'params' in site:
            url_parts = list(urlparse.urlparse(url))
            query = dict(urlparse.parse_qsl(url_parts[4]))
            query.update(site['params'])
            url_parts[4] = urlencode(query)
            url = urlparse.urlunparse(url_parts)

        response_text = ''
        if 'response_text' in site:
            response_text = site['response_text']
        elif 'response_json' in site:
            response_text = json.dumps(site['response_json'])
        elif 'response_file' in site:
            with open(datadir / site['response_file']) as f:
                response_text = f.read().strip()

        request_text = None
        if 'request_text' in site:
            request_text = site['request_text']
        elif 'request_json' in site:
            request_text = json.dumps(site['request_json'])
        elif 'request_file' in site:
            with open(datadir / site['request_file']) as f:
                request_text = f.read().strip()

        requests_mock.register_uri(
            site.get('method', 'GET'),
            url,
            request_headers = site.get('headers', {}),
            status_code = site.get('status_code', 200),
            text = response_text,
            additional_matcher = create_validation_callback(request_text),
        )

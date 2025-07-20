import pytest

from saq.configuration.config import get_config
from saq.proxy import proxies

INVALID_KEY = "WrongKey"

@pytest.mark.unit
def test_global_proxy():
    proxy = proxies()
    assert proxies != None
    assert proxies

@pytest.mark.unit
def test_wrong_key_raises():
    with pytest.raises(KeyError):
        proxy = proxies(INVALID_KEY)

@pytest.mark.unit
def test_proxy_config():
    get_config()['proxy']['transport'] = 'http'
    get_config()['proxy']['host'] = 'proxy.local'
    get_config()['proxy']['port'] = '3128'

    assert proxies() == {
        'http': 'http://proxy.local:3128',
        'https': 'http://proxy.local:3128',
    }

    get_config()['proxy']['transport'] = 'http'
    get_config()['proxy']['host'] = 'proxy.local'
    get_config()['proxy']['port'] = '3128'
    get_config()['proxy']['user'] = 'ace'
    get_config()['proxy']['password'] = '1234'

    assert proxies() == {
        'http': 'http://ace:1234@proxy.local:3128',
        'https': 'http://ace:1234@proxy.local:3128',
    }

# vim: sw=4:ts=4:et
#
# ACE proxy settings

import urllib
from saq.configuration import get_config
from saq.constants import CONFIG_PROXY, G_OTHER_PROXIES
from saq.environment import g_dict


GLOBAL_PROXY_KEY = 'global'

def proxy_config(key):
    if key is None:
        return {}
    return g_dict(G_OTHER_PROXIES)[key]

def proxies(key=None):
    """Returns the current proxy settings pulled from the configuration.
       Parameters:
       key - a key to select a proxy other than the default globally configured one
       Returns a dict in the following format. ::

    {
        'http': 'url',
        'https': 'url'
    }
"""
    config = None
    if key:
        return g_dict(G_OTHER_PROXIES)[key]
    else:
        config = get_config()[CONFIG_PROXY]
    
    # set up the PROXY global dict (to be used with the requests library)
    result = {}
    for proxy_key in [ 'http', 'https' ]:
        if config['host'] and config['port'] and config['transport']:
            if config['user'] and config['password']:
                result[proxy_key] = '{}://{}:{}@{}:{}'.format(
                    config['transport'], 
                    urllib.parse.quote_plus(config['user']), 
                    urllib.parse.quote_plus(config['password']), 
                    config['host'], 
                    config['port'])
            else:
                result[proxy_key] = '{}://{}:{}'.format(config['transport'], 
                                                        config['host'], 
                                                        config['port'])

    return result

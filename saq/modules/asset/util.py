# some utility functions
import re


valid_ipv4_regex = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
def is_ipv4(value):
    return valid_ipv4_regex.match(value) is not None

valid_hostname_regex = re.compile(r'^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$')
def is_hostname(value):
    if value == '':
        return False

    if is_ipv4(value):
        return False

    return valid_hostname_regex.match(value) is not None

def is_fqdn(value):
    if not is_ipv4(value) and not is_hostname(value) and '.' in value:
        return True

    return False
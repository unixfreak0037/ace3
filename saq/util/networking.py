import re

from saq.configuration.config import get_config


CIDR_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$')
CIDR_WITH_NETMASK_REGEX = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$')
URL_REGEX_B = re.compile(rb'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\\\w:%\?&;=-]*))?(?<!=))', re.I)
URL_REGEX_STR = re.compile(r'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\\\w:%\?&;=-]*))?(?<!=))', re.I)

def is_ipv4(value):
    """Returns True if the given value is a dotted-quad IP address or CIDR notation."""
    return CIDR_REGEX.match(value) is not None

def add_netmask(value):
    """Returns a CIDR notation value for the given ipv4 or CIDR notation (adds the network if it's missing.)"""
    if CIDR_WITH_NETMASK_REGEX.match(value):
        return value

    # we assume it is a single host
    return '{}/32'.format(value)

def is_subdomain(src, dst):
    """Returns True if src is equal to or a subdomain of dst."""
    src = src.lower()
    src = src.split('.')
    src.reverse()
    
    dst = dst.lower()
    dst = dst.split('.')
    dst.reverse()

    for index in range(len(dst)):
        try:
            if src[index] != dst[index]:
                return False
        except IndexError:
            return False

    return True

def is_url(value):
    if isinstance(value, str):
        if URL_REGEX_STR.match(value):
            return True

        return False
    else:
        if URL_REGEX_B.match(value):
            return True

        return False

def iterate_fqdn_parts(fqdn, reverse=False):
    """For a.b.c.d iterates d, c.d, b.c.d, a.b.c.d."""
    parsed_fqdn = fqdn.split('.')
    parsed_fqdn.reverse()
    for i in range(1, len(parsed_fqdn) + 1):
        partial_fqdn = parsed_fqdn[:i]
        partial_fqdn.reverse()
        partial_fqdn = '.'.join(partial_fqdn)
        yield partial_fqdn

    return

def fully_qualified(hostname: str) -> str:
    """Returns the hostname fully qualified with the configured local domain.
    If local domain is not set in the [global] section then hostname is returned unchanged.
    If hostname *looks* already fully qualified then hostname is returned unchanged."""
    if not hostname:
        return None

    if "." in hostname:
        return hostname

    local_domain = get_config()["global"].get("local_domain", "")
    if not local_domain:
        return hostname

    return f"{hostname}.{local_domain}"
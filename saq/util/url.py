import urllib
from saq.constants import F_URL


def fang(url):
    """Re-fangs a url that has been de-fanged.
    If url does not match the defang format, it returns the original string."""
    _formats = ['hxxp', 'hXXp']
    for item in _formats:
        if url.startswith(item):
            return f"http{url[4:]}"
    return url

def find_all_url_domains(analysis):
    from saq.analysis import Analysis
    assert isinstance(analysis, Analysis)
    domains = {}
    for observable in analysis.find_observables(lambda o: o.type == F_URL):
        hostname = urllib.parse.urlparse(observable.value).hostname
        if hostname is None:
            continue

        if hostname not in domains:
            domains[hostname] = 1
        else:
            domains[hostname] += 1

    return domains
import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from saq.analysis.observable import Observable
from saq.configuration.config import get_config_value_as_list
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_DOMAINS, CONFIG_GLOBAL_LOCAL_EMAIL_DOMAINS, F_URI_PATH, F_URL, F_USER_AGENT
from saq.gui import ObservableActionSeparator, ObservableActionUrlCrawl, ObservableActionUrlscan
from saq.observables.generator import map_observable_type
from saq.remediation import RemediationTarget
from urlfinderlib.url import URL
from urlfinderlib import find_urls

from saq.util import is_subdomain


class UserAgentObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_USER_AGENT, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()



class URIPathObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_URI_PATH, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    def is_managed(self) -> bool:
        for parent in self.parents:
            if parent.observable and parent.observable.is_managed():
                return True

        return False


PROTECTED_URLS = ['egnyte.com', 'fireeye.com', 'safelinks.protection.outlook.com', 'dropbox.com', 'drive.google.com', '.sharepoint.com',
                  'proofpoint.com', 'urldefense.com']


class URLObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_URL, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        # Extract URL from known protected URLs, if necessary
        if any(url in self.value for url in PROTECTED_URLS):
            self.sanitize_protected_urls()

        # Use urlfinderlib to make sure this is a valid URL before creating the observable
        # XXX not worker after upgrade
        #if not is_url(self.value):
            #raise ObservableValueError("invalid URL {}".format(self.value))

    @property
    def jinja_available_actions(self):
        result = [
            ObservableActionUrlscan(),
            ObservableActionUrlCrawl(),
            ObservableActionSeparator(),
        ]
        result.extend(super().jinja_available_actions)
        return result

    @property
    def remediation_targets(self):
        if self.is_managed():
            return []
        return [RemediationTarget('zerofox_threat', self.value)]

    def is_managed(self):
        """Returns True if this URL has a managed domain."""

        url = URL(self.value)
        for fqdn in get_config_value_as_list(CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_DOMAINS):
            if is_subdomain(url.netloc_idna, fqdn):
                return True

        for fqdn in get_config_value_as_list(CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_EMAIL_DOMAINS):
            if is_subdomain(url.netloc_idna, fqdn):
                return True

        return False

    def sanitize_protected_urls(self):
        """Is this URL protected by another company by wrapping it inside another URL they check first?"""

        extracted_url = None

        try:
            parsed_url = urlparse(self.value)
        except Exception as e:
            logging.error("unable to parse url {}: {}".format(self.value, e))
            return

        # egnyte links
        if parsed_url.netloc.lower().endswith('egnyte.com'):
            if parsed_url.path.startswith('/dl/'):
                extracted_url = self.value.replace('/dl/', '/dd/')
                logging.info("translated egnyte.com url {} to {}".format(self.value, extracted_url))

        # fireeye links
        elif parsed_url.netloc.lower().endswith('fireeye.com'):
            if parsed_url.netloc.lower().startswith('protect'):
                qs = parse_qs(parsed_url.query)
                if 'u' in qs:
                    extracted_url = qs['u'][0]

        # "safelinks" by outlook
        elif parsed_url.netloc.lower().endswith('safelinks.protection.outlook.com'):
            qs = parse_qs(parsed_url.query)
            if 'url' in qs:
                extracted_url = qs['url'][0]

        # dropbox links
        elif parsed_url.netloc.lower().endswith('.dropbox.com'):
            qs = parse_qs(parsed_url.query)
            modified = False
            if 'dl' in qs:
                if qs['dl'] == ['0']:
                    qs['dl'] = '1'
                    modified = True
            else:
                qs['dl'] = '1'
                modified = True

            if modified:
                # rebuild the query
                extracted_url = urlunparse((parsed_url.scheme,
                                           parsed_url.netloc,
                                           parsed_url.path,
                                           parsed_url.params,
                                           urlencode(qs),
                                           parsed_url.fragment))

        # sharepoint download links
        elif parsed_url.netloc.lower().endswith('.sharepoint.com'):
            # user gets this link in an email
            # https://lahia-my.sharepoint.com/:b:/g/personal/secure_onedrivemsw_bid/EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ?e=naeXYD
            # needs to turn into this link
            # https://lahia-my.sharepoint.com/personal/secure_onedrivemsw_bid/_layouts/15/download.aspx?e=naeXYD&share=EVdjoBiqZTxMnjAcDW6yR4gBqJ59ALkT1C2I3L0yb_n0uQ

            # so the URL format seems to be this
            # https://SITE.shareponit.com/:b:/g/PATH/ID?e=DATA
            # not sure if NAME can contain subdirectories so we'll assume it can
            regex_sharepoint = re.compile(r'^/:b:/g/(.+)/([^/]+)$')
            m = regex_sharepoint.match(parsed_url.path)
            parsed_qs = parse_qs(parsed_url.query)
            if m and 'e' in parsed_qs:
                extracted_url = urlunparse((parsed_url.scheme,
                                            parsed_url.netloc,
                                            '/{}/_layouts/15/download.aspx'.format(m.group(1)),
                                            parsed_url.params,
                                            urlencode({'e': parsed_qs['e'][0], 'share': m.group(2)}),
                                            parsed_url.fragment))

                logging.info("translated sharepoint url {} to {}".format(self.value, extracted_url))

        # google drive links
        regex_google_drive = re.compile(r'drive\.google\.com/file/d/([^/]+)/view')
        m = regex_google_drive.search(self.value)
        if m:
            # sample
            # https://drive.google.com/file/d/1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2/view
            # turns into
            # https://drive.google.com/uc?authuser=0&id=1ls_eBCsmf3VG_e4dgQiSh_5VUM10b9s2&export=download

            google_id = m.group(1)

            extracted_url = 'https://drive.google.com/uc?authuser=0&id={}&export=download'.format(google_id)
            logging.info("translated google drive url {} to {}".format(self.value, extracted_url))

        if parsed_url.netloc.lower().endswith('urldefense.com'):
            regex_ud = re.compile(r'^https://urldefense\.com/v3/__(.+?)__.+$')
            m = regex_ud.match(self.value)
            if m:
                extracted_url = m.group(1)
                logging.info(f"translated urldefense.com url {self.value} to {extracted_url}")

        if parsed_url.netloc.lower().endswith('.proofpoint.com'):
            extracted_url_set = find_urls(self.value)
            if extracted_url_set:
                # loop through all extrected URLs to remove any nested protected URLs
                for possible_url in extracted_url_set.copy():
                    if any(url in possible_url for url in PROTECTED_URLS):
                        extracted_url_set.remove(possible_url)

                # make sure that the set still has URLs in it
                if extracted_url_set:
                    extracted_url = extracted_url_set.pop()

        # Add additional simple protected URL sanitizaitons here
        # If sanitization requires redirect/additional analysis, add to saq.modules.url.ProtectedURLAnalyzer

        # return junk if this a malformed protected URL/proofpoint entaglement so we don't add it as an observable
        if not extracted_url and 'proofpoint.com' in self.value:
            extracted_url = 'NOT_A_URL'

        if extracted_url:
            self.value = extracted_url

map_observable_type(F_USER_AGENT, UserAgentObservable)
map_observable_type(F_URI_PATH, URIPathObservable)
map_observable_type(F_URL, URLObservable)
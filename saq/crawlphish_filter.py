# vim: sw=4:ts=4:et:cc=120
#

import logging
import os.path
import re
from ipaddress import IPv4Network, IPv4Address
from urllib.parse import urlparse

from saq.brocess import query_brocess_by_fqdn
from saq.configuration import get_config
from saq.environment import get_base_dir, get_data_dir
from saq.error import report_exception
from saq.util import is_ipv4, is_subdomain, iterate_fqdn_parts, add_netmask

analysis_module = 'analysis_module_crawlphish'

__all__ = [
    'REASON_ERROR',
    'REASON_UNKNOWN',
    'REASON_WHITELISTED',
    'REASON_BLACKLISTED',
    'REASON_COMMON_NETWORK',
    'REASON_DIRECT_IPV4',
    'REASON_OK',
    'process_url',
    'CrawlphishURLFilter',
]

REASON_ERROR =          'ERROR'
REASON_UNKNOWN =        'UNKNOWN'
REASON_WHITELISTED =    'WHITELISTED'
REASON_BLACKLISTED =    'BLACKLISTED'
REASON_COMMON_NETWORK = 'COMMON_NETWORK'
REASON_DIRECT_IPV4 =    'DIRECT_IPV4'
REASON_OK =             'OK'

SCHEMA_REGEX = re.compile('^[a-zA-Z]+://')

def process_url(url):
    m = SCHEMA_REGEX.search(url)
    if m is None:
        logging.debug("adding missing schema to url {}".format(url))
        url = 'http://{}'.format(url)

    # make sure the url is valid
    parsed_url = urlparse(url)

    if not parsed_url.netloc:
        logging.debug("no netloc for {}".format(url))
        return None

    return parsed_url

class FilterResult:
    def __init__(self):
        # was it filtered
        self.filtered = False
        # why was it filtered (or not filtered)
        self.reason = REASON_UNKNOWN
        # result of urlparse on reformatted url
        self.parsed_url = None

    def __bool__(self):
        return self.filtered

class CrawlphishURLFilter:

    def __init__(
        self, 
        blacklist_filter_enabled=True, 
        whitelist_filter_enabled=True, 
        path_regex_filter_enabled=True, 
        common_filter_enabled=True,
        intel_filter_enabled=True,
        direct_ipv4_filter_enabled=True):

        self.blacklisted_cidr = []
        self.blacklisted_fqdn = []
        self.whitelisted_cidr = []
        self.whitelisted_fqdn = []
        self.path_regexes = []

        self.blacklist_filter_enabled = blacklist_filter_enabled
        self.whitelist_filter_enabled = whitelist_filter_enabled
        self.path_regex_filter_enabled = path_regex_filter_enabled
        self.common_filter_enabled = common_filter_enabled
        self.intel_filter_enabled = intel_filter_enabled
        self.direct_ipv4_filter_enabled = direct_ipv4_filter_enabled

    def load(self):
        self.load_whitelist()
        self.load_blacklist()
        self.load_path_regexes()

    @property
    def whitelist_path(self):
        path = get_config()[analysis_module]['whitelist_path']
        if os.path.isabs(path):
            return path

        return os.path.join(get_base_dir(), path)

    @property
    def blacklist_path(self):
        path = get_config()[analysis_module]['blacklist_path']
        if os.path.isabs(path):
            return path

        return os.path.join(get_base_dir(), path)

    @property
    def regex_path(self):
        path = get_config()[analysis_module]['regex_path']
        if os.path.isabs(path):
            return path

        return os.path.join(get_base_dir(), path)

    def load_whitelist(self):
        logging.debug("loading whitelist from {}".format(self.whitelist_path))
        whitelisted_fqdn = []
        whitelisted_cidr = []

        if not os.path.exists(self.whitelist_path):
            logging.debug("whitelist {} does not exist".format(self.whitelist_path))
            return

        try:
            with open(self.whitelist_path, 'r') as fp:
                for line in fp:
                    line = line.strip()

                    # skip comments
                    if line.startswith('#'):
                        continue

                    # skip blank lines
                    if line == '':
                        continue

                    if is_ipv4(line):
                        whitelisted_cidr.append(IPv4Network(add_netmask(line)))
                    else:
                        whitelisted_fqdn.append(line)

            self.whitelisted_cidr = whitelisted_cidr
            self.whitelisted_fqdn = whitelisted_fqdn
            logging.debug("loaded {} cidr {} fqdn whitelisted items".format(
                           len(self.whitelisted_cidr),
                           len(self.whitelisted_fqdn)))

        except Exception as e:
            logging.error("unable to load whitelist {}: {}".format(self.whitelist_path, e))
            report_exception()

    def is_whitelisted(self, value):
        if is_ipv4(value):
            for cidr in self.whitelisted_cidr:
                if IPv4Address(value) in cidr:
                    logging.debug("{} matches whitelisted cidr {}".format(value, cidr))
                    return True

            return False

        for dst in self.whitelisted_fqdn:
            if is_subdomain(value, dst):
                logging.debug("{} matches whitelisted fqdn {}".format(value, dst))
                return True

        return False

    def load_blacklist(self):
        logging.debug("loading blacklist from {}".format(self.blacklist_path))
        blacklisted_fqdn = []
        blacklisted_cidr = []

        if not os.path.exists(self.blacklist_path):
            logging.debug("blacklist {} does not exist".format(self.blacklist_path))
            return

        try:
            with open(self.blacklist_path, 'r') as fp:
                for line in fp:
                    line = line.strip()

                    # skip comments
                    if line.startswith('#'):
                        continue

                    # skip blank lines
                    if line == '':
                        continue

                    if is_ipv4(line):
                        blacklisted_cidr.append(IPv4Network(add_netmask(line)))
                    else:
                        blacklisted_fqdn.append(line)

            self.blacklisted_cidr = blacklisted_cidr
            self.blacklisted_fqdn = blacklisted_fqdn
            logging.debug("loaded {} cidr {} fqdn blacklisted items".format(
                           len(self.blacklisted_cidr),
                           len(self.blacklisted_fqdn)))

        except Exception as e:
            logging.error("unable to load blacklist {}: {}".format(self.blacklist_path, e))
            report_exception()

    def load_path_regexes(self):
        logging.debug("loading path regexes from {}".format(self.regex_path))
        path_regexes = []

        if not os.path.exists(self.regex_path):
            logging.debug("path regexes {} does not exist".format(self.regex_path))
            return

        try:
            with open(self.regex_path, 'r') as fp:
                for line in fp:
                    line = line.strip()

                    # skip comments
                    if line.startswith('#'):
                        continue

                    # skip blank lines
                    if line == '':
                        continue

                    # try to compile it
                    try:
                        path_regexes.append(re.compile(line, re.I))
                    except Exception as e:
                        logging.error("regular expression {} does not compile: {}".format(line, e))

            self.path_regexes = path_regexes
            logging.debug("loaded {} path regexes".format(len(self.path_regexes)))

        except Exception as e:
            logging.error("unable to load path regexes from {}: {}".format(self.regex_path, e))
            report_exception()

    def is_blacklisted(self, value):
        if is_ipv4(value):
            for cidr in self.blacklisted_cidr:
                try:
                    if IPv4Address(value) in cidr:
                        logging.debug("{} matches blacklisted cidr {}".format(value, cidr))
                        return True
                except Exception as e:
                    logging.error("failed to compare {} to {}: {}".format(value, cidr, e))
                    report_exception()

            return False

        for dst in self.blacklisted_fqdn:
            if is_subdomain(value, dst):
                logging.debug("{} matches blacklisted fqdn {}".format(value, dst))
                return True

        return False

    def matches_path_regex(self, url):
        for path_regex in self.path_regexes:
            if path_regex.search(url):
                logging.debug("{} matches patch regex {}".format(url, path_regex))
                return True

        return False

    def is_in_intel_db(self, value):
        """Returns True if the given value is in your intel database, False otherwise."""
        result = False
        if 'sip' in get_config() and get_config()['sip'].getboolean('enabled'):
            result |= self.is_in_sip(value)

        return result

    def is_in_sip(self, value):
        try:
            return self.is_in_cache_db(value, os.path.join(get_data_dir(), get_config()['sip']['cache_db_path']))
        except Exception as e:
            logging.error(f"is_in_sip failed: {e}")

    def _is_uncommon_fqdn(self, fqdn):
        """Returns True if the given fqnd is considered "uncommon"."""
        # consider a.b.c.d
        # if d is common then we want to see if c.d is uncommon
        # if c.d is common then we look at b.c.d, and so forth
        # if they are all common then we return False
        for partial_fqdn in iterate_fqdn_parts(fqdn):
            count = query_brocess_by_fqdn(partial_fqdn)

            if count is None:
                continue

            if count < get_config()[analysis_module].getint('uncommon_network_threshold'):
                logging.info("{} is an uncommon network with count {}".format(partial_fqdn, count))
                return True
            else:
                pass
                #logging.debug("{} is a common network with count {}".format(partial_fqdn, count))

        return False
        
    def is_uncommon_network(self, value):
        try:
            return self._is_uncommon_fqdn(value)
        except Exception as e:
            logging.error("unable to query brocess: {}".format(e))
            report_exception()
            return False

    def filter(self, url):
        """Returns True if the given URL should be filtered (not crawled).  Check the reason property
           the reason the url is filtered."""
        result = FilterResult()
        result.filtered = False
        result.reason = REASON_UNKNOWN

        result.parsed_url = process_url(url)
        if not result.parsed_url:
            logging.debug("unable to process url {}".format(url))
            result.reason = REASON_ERROR
            return result

        logging.debug("analyzing scheme {} netloc {} hostname {} path {} params {} query {} fragment {}".format(
                      result.parsed_url.scheme,
                      result.parsed_url.netloc,
                      result.parsed_url.hostname,
                      result.parsed_url.path,
                      result.parsed_url.params,
                      result.parsed_url.query,
                      result.parsed_url.fragment))

        if self.whitelist_filter_enabled and self.is_whitelisted(result.parsed_url.hostname):
            result.reason = REASON_WHITELISTED
            result.filtered = False
            return result

        if self.blacklist_filter_enabled and self.is_blacklisted(result.parsed_url.hostname):
            result.reason = REASON_BLACKLISTED
            result.filtered = True
            return result

        # if the URL is just to an IP address then we crawl that no matter what
        if self.direct_ipv4_filter_enabled and is_ipv4(result.parsed_url.hostname):
            result.reason = REASON_DIRECT_IPV4
            result.filtered = False
            return result

        if result.parsed_url.path:
            if self.path_regex_filter_enabled and self.matches_path_regex(result.parsed_url.path):
                result.reason = REASON_WHITELISTED
                result.filtered = False
                return result
            
        if self.common_filter_enabled and not self.is_uncommon_network(result.parsed_url.hostname):
            result.reason = REASON_COMMON_NETWORK
            result.filtered = True
            return result

        result.filtered = False
        result.reason = REASON_OK
        return result

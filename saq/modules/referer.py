import logging

from saq.analysis import Analysis
from saq.constants import AnalysisExecutionResult
from saq.database import get_db_connection
from saq.modules import AnalysisModule
from saq.modules.asset import NetworkIdentifierAnalysis
from saq.modules.dns import FQDNAnalysis
from saq.modules.url import ParseURLAnalysis
from saq.constants import F_URL, F_FQDN, F_IPV4, F_ASSET, DIRECTIVE_PHISHKIT, DIRECTIVE_SCAN_URLSCAN

KEY_HEURISTIC_RESULT = "heuristic_result"
KEY_HEURISTIC_DETAILS = "heuristic_details"

def is_autotuned(_type: str, _value: str) -> bool:
    """Returns True if this observable has already been analyzed."""
    with get_db_connection() as db:
        c = db.cursor()
        sql = """
        SELECT count(*)
        FROM observables o JOIN observable_tag_index oti ON oti.observable_id = o.id
        JOIN observable_mapping om ON om.observable_id = o.id
        JOIN alerts a ON om.alert_id = a.id
        WHERE
            o.`type` = %s
            AND o.`value` = %s
            AND a.alert_type = 'hunter - splunk - referer'
            AND a.disposition = 'FALSE_POSITIVE'
        """
        c.execute(sql, (_type, _value))

        result = c.fetchone()
        if not result:
            return False

        return result[0] > 0


class HTTPRefererAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            KEY_HEURISTIC_RESULT: None,
            KEY_HEURISTIC_DETAILS: None,
        }

    @property
    def heuristic_result(self) -> bool:
        """Returns True if all heuristic checks passed, False otherwise."""
        return self.details.get(KEY_HEURISTIC_RESULT, None)

    @heuristic_result.setter
    def heuristic_result(self, value: bool):
        self.details[KEY_HEURISTIC_RESULT] = value

    @property
    def heuristic_details(self) -> str:
        """Returns the description of why the (or which) heuristic check failed, or None."""
        return self.details.get(KEY_HEURISTIC_DETAILS, None)

    @heuristic_details.setter
    def heuristic_details(self, value: str):
        self.details[KEY_HEURISTIC_DETAILS] = value

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if not self.heuristic_result:
            return f"HTTP Referer Analysis: OK: {self.heuristic_details}"
        else:
            return "HTTP Referer Analysis: Suspect"

class HTTPRefererAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return HTTPRefererAnalysis

    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def required_tags(self):
        return [ "referer" ]

    def execute_analysis(self, url) -> AnalysisExecutionResult:
        # have we already analyzed this url?
        if is_autotuned(F_URL, url.value):
            logging.info("url %s has already been analyzed before and FP'd", url.value)
            return AnalysisExecutionResult.COMPLETED

        url_analysis = self.wait_for_analysis(url, ParseURLAnalysis)
        fqdn = url_analysis.get_observables_by_type(F_FQDN)
        if not fqdn:
            logging.info("unable to parse fqdn from phishkit url %s", url.value)
            return AnalysisExecutionResult.COMPLETED

        fqdn = fqdn[0]

        # have we already analyzed this fqdn?
        if is_autotuned(F_FQDN, fqdn.value):
            logging.info("fqdn %s has already been analyzed before and FP'd", fqdn.value)
            return AnalysisExecutionResult.COMPLETED

        # domain has to resolve to something
        dns_analysis = self.wait_for_analysis(fqdn, FQDNAnalysis)
        if not dns_analysis:
            logging.info("domain %s did not resolve", fqdn.value)
            return AnalysisExecutionResult.COMPLETED

        ipv4 = dns_analysis.get_observables_by_type(F_IPV4)
        if not ipv4:
            logging.info("domain %s did not resolve", fqdn.value)
            return AnalysisExecutionResult.COMPLETED

        ipv4 = ipv4[0]
        
        network_id = self.wait_for_analysis(ipv4, NetworkIdentifierAnalysis)
        asset = network_id.get_observables_by_type(F_ASSET)

        if asset:
            logging.info("domain %s resolves to hosted IP address", fqdn.value)
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(url)
        analysis.heuristic_result = True
        analysis.heuristic_details = None
        # at this point we need to check to see if this is a phishkit referencing our stuff
        url.add_directive(DIRECTIVE_PHISHKIT)
        url.add_directive(DIRECTIVE_SCAN_URLSCAN)
        fqdn.add_tag("referer")

        return AnalysisExecutionResult.COMPLETED

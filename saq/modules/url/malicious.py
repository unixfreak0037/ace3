import logging
from urllib.parse import urlparse
from saq.analysis.analysis import Analysis
from saq.constants import F_FQDN, F_URL, AnalysisExecutionResult
from saq.modules import AnalysisModule


KEY_FQDN = 'fqdn'
KEY_ERROR = 'error'

class MaliciousURLAnalysis(Analysis):
    """If this URL is tagged as malicious, then let's look at the various components of it."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_FQDN: None,
            KEY_ERROR: None,
        }

    @property
    def fqdn(self):
        return self.details[KEY_FQDN]

    @fqdn.setter    
    def fqdn(self, value):
        self.details[KEY_FQDN] = value

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.detais[KEY_ERROR] = value

    def generate_summary(self):
        result = "Malicious URL Analyzer: "

        if self.error is not None:
            return result + self.error
        elif self.fqdn is None:
            return None

        return result + f"fqdn {self.fqdn.value}"

class MaliciousURLAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MaliciousURLAnalysis

    @property
    def required_tags(self):
        return [ 'malicious' ]

    @property
    def valid_observable_types(self):
        return [ F_URL ]

    def execute_analysis(self, url) -> AnalysisExecutionResult:

        analysis = self.create_analysis(url)

        try:
            parsed_url = urlparse(url.value)
            if parsed_url.hostname is not None:
                fqdn = analysis.add_observable_by_spec(F_FQDN, parsed_url.hostname)
                fqdn.add_tag('malicious')
                analysis.fqdn = fqdn
        except Exception as e:
            logging.warning(f"unable to parse url {url.value}: {e}")
            analysis.error = str(e)

        return AnalysisExecutionResult.COMPLETED
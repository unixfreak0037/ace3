# utility class to translate custom objects into JSON
from datetime import datetime
import json

from saq.constants import EVENT_TIME_FORMAT_JSON_TZ, AnalysisExecutionResult

import yara


class _JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        from saq.analysis.root import RootAnalysis
        if isinstance(obj, datetime):
            return obj.strftime(EVENT_TIME_FORMAT_JSON_TZ)
        elif isinstance(obj, bytes):
            return obj.decode('unicode_escape', 'replace')
        elif isinstance(obj, RootAnalysis):
            return obj.json
        elif hasattr(obj, 'json'):
            return obj.json
        elif isinstance(obj, yara.StringMatch):
            return {
                "identifier": obj.identifier,
                "instances": obj.instances,
                "is_xor": obj.is_xor(),
            }
        elif isinstance(obj, AnalysisExecutionResult):
            return obj.value
        elif isinstance(obj, yara.StringMatchInstance):
            return {
                "matched_data": obj.matched_data,
                "matched_length": obj.matched_length,
                "offset": obj.offset,
                "plaintext": obj.plaintext(),
                "xor_key": obj.plaintext(),
            }
        else:
            raise ValueError("unsupported type passed to _JSONEncoder", type(obj))

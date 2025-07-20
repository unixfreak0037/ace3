import pytest

from saq.analysis import RootAnalysis
from saq.configuration import get_config
from saq.constants import DISPOSITION_FALSE_POSITIVE, DIRECTIVE_PHISHKIT, DIRECTIVE_SCAN_URLSCAN, F_URL, F_FQDN, F_IPV4, F_ASSET, G_AUTOMATION_USER_ID, AnalysisExecutionResult
from saq.database import ALERT, set_dispositions

from saq.environment import g_int
from saq.modules.asset import NetworkIdentifierAnalysis
from saq.modules.dns import FQDNAnalysis
from saq.modules.referer import is_autotuned, HTTPRefererAnalyzer
from saq.modules.url import ParseURLAnalysis
from saq.modules.adapter import AnalysisModuleAdapter

@pytest.mark.integration
def test_is_autotuned(tmpdir):
    storage_dir = str(tmpdir / "storage")
    root = RootAnalysis(tool="test", tool_instance="test", alert_type="hunter - splunk - referer", storage_dir=storage_dir)
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://www.evil.com/")
    url.add_tag("referer")
    root.save()
    alert = ALERT(root)
    set_dispositions([alert.uuid], DISPOSITION_FALSE_POSITIVE, g_int(G_AUTOMATION_USER_ID))

    assert is_autotuned(F_URL, url.value)

@pytest.mark.parametrize("autotune_result,dns_resolution,asset_query,execute_analysis_result", [
    (False, "1.2.3.4", None, True), # everything checks out
    (False, "1.2.3.4", "1.2.3.4", False), # resolves to hosted ip address
    (False, None, None, False), # does not resolve
    (True, None, None, False), # autotuned
])
@pytest.mark.integration
def test_referer_analysis(autotune_result, dns_resolution, asset_query, execute_analysis_result, tmpdir, monkeypatch, test_context):
    import saq.modules.referer
    monkeypatch.setattr(saq.modules.referer, "is_autotuned", lambda _type, _value: autotune_result)

    storage_dir = str(tmpdir / "storage")
    get_config()['analysis_module_config'] = {}
    root = RootAnalysis(tool="test", tool_instance="test", alert_type="hunter - splunk - referer", storage_dir=storage_dir)
    root.initialize_storage()
    url = root.add_observable_by_spec(F_URL, "https://www.evil.com/")
    url.add_tag("referer")

    analysis = ParseURLAnalysis()
    url.add_analysis(analysis)
    fqdn = analysis.add_observable_by_spec(F_FQDN, "www.evil.com")

    analysis = FQDNAnalysis()
    fqdn.add_analysis(analysis)
    if dns_resolution:
        ipv4 = analysis.add_observable_by_spec(F_IPV4, dns_resolution)

        analysis = NetworkIdentifierAnalysis()
        ipv4.add_analysis(analysis)
        if asset_query:
            asset = analysis.add_observable_by_spec(F_ASSET, asset_query)

    analyzer = AnalysisModuleAdapter(HTTPRefererAnalyzer(context=test_context))

    analyzer.root = root
    assert analyzer.execute_analysis(url) == AnalysisExecutionResult.COMPLETED

    if execute_analysis_result:
        analysis = url.get_analysis(analyzer.generated_analysis_type)
        assert analysis.heuristic_result
        assert analysis.heuristic_details is None
        assert url.has_directive(DIRECTIVE_PHISHKIT)
        assert url.has_directive(DIRECTIVE_SCAN_URLSCAN)
        assert fqdn.has_tag("referer")

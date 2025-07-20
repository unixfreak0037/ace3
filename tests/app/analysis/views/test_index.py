import shutil
from uuid import uuid4
from flask import url_for
import pytest

from saq.analysis.module_path import MODULE_PATH
from saq.constants import F_TEST
from saq.database.model import Alert
from saq.database.util.alert import ALERT
from saq.observables.testing import TestObservable
from saq.modules.adapter import AnalysisModuleAdapter

@pytest.mark.system
def test_index(web_client, root_analysis, api_server, test_context):
    result = web_client.get(url_for("analysis.index"), query_string={"direct": str(uuid4())})

    # unknown uuid should return redirect to manage
    assert result.status_code == 302
    assert result.location == url_for("analysis.manage")

    test_observable = root_analysis.add_observable_by_spec(F_TEST, "test_1")
    assert isinstance(test_observable, TestObservable)

    from saq.modules.test import BasicTestAnalyzer, BasicTestAnalysis
    analyzer = AnalysisModuleAdapter(BasicTestAnalyzer(context=test_context))
    analyzer.root = root_analysis
    analyzer.execute_analysis(test_observable)
    analysis = test_observable.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(analysis, BasicTestAnalysis)

    root_analysis.save() # TODO ALERT should save()
    alert = ALERT(root_analysis)
    assert isinstance(alert, Alert)

    result = web_client.get(url_for("analysis.index"), query_string={
            "direct": root_analysis.uuid,
            "observable_uuid": test_observable.id,
            "module_path": MODULE_PATH(analysis),
        })
    assert result.status_code == 200

@pytest.mark.integration
def test_index_no_load(web_client, root_analysis):
    """Alert JSON is missing."""
    root_analysis.save() # TODO ALERT should save()
    alert = ALERT(root_analysis)
    assert isinstance(alert, Alert)

    shutil.rmtree(alert.storage_dir)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})
    assert result.status_code == 302
    assert result.location == url_for("analysis.manage")

from flask import url_for
import pytest

from saq.database.model import Alert
from saq.database.util.alert import ALERT

@pytest.mark.integration
def test_manage(web_client, root_analysis):
    root_analysis.save() # TODO ALERT should save()
    alert = ALERT(root_analysis)
    assert isinstance(alert, Alert)

    result = web_client.get(url_for("analysis.manage"))
    assert result.status_code == 200
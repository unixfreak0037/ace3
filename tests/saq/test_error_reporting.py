import os
import pytest

from saq.configuration.config import get_config
from saq.environment import get_data_dir
from saq.error.reporting import report_exception

@pytest.mark.integration
def test_report_exception():
    try:
        1 / 0
    except Exception as e:
        report_exception()

    error_reporting_dir = os.path.join(get_data_dir(), get_config()['global']['error_reporting_dir'])
    assert len(os.listdir(error_reporting_dir)) == 1
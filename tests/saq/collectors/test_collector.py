import os
import os.path
import pickle
from typing import Generator, Optional, override

import pytest

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import CollectorService, get_collection_error_dir
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.collectors.remote_node import save_submission_for_review
from saq.configuration import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, ANALYSIS_TYPE_MANUAL
from saq.collectors.base_collector import Collector

import pymysql.err

class TestCollector(Collector):
    __test__ = False
    
    @override
    def collect(self) -> Generator[Submission, None, None]:
        if False:
            yield  # This is a stub to satisfy the type checker and linter.

    @override
    def update(self) -> None:
        pass

    @override
    def cleanup(self) -> None:
        pass

@pytest.mark.unit
def test_save_submission_for_review(monkeypatch, tmpdir, root_analysis):
    submission = Submission(root_analysis)
    assert len(os.listdir(get_collection_error_dir())) == 0
    save_submission_for_review(submission)
    storage_dir = os.path.join(get_collection_error_dir(), submission.root.uuid)
    assert os.path.exists(storage_dir)
    root = RootAnalysis(storage_dir=storage_dir)
    root.load()

    assert root.uuid == submission.root.uuid

@pytest.mark.unit
def test_schedule_submission_interface_error_no_recovery(root_analysis, monkeypatch):
    # configure the collector
    get_config()['service_generic_collector'] = { 
        "workload_type": "generic",
        "delete_files": "yes",
    }

    collector = CollectorService(
        collector=TestCollector(), 
        config=CollectorServiceConfiguration.from_config(get_config()['service_generic_collector']))
    assert collector.submission_scheduler is not None

    import saq.collectors.workload_repository
    def mock_execute_with_retry(*args, **kwargs):
        raise pymysql.err.InterfaceError(0, "")

    monkeypatch.setattr(saq.collectors.workload_repository, "execute_with_retry", mock_execute_with_retry)
    with pytest.raises(pymysql.err.InterfaceError):
        collector.submission_scheduler.schedule_submission(Submission(root_analysis), collector.remote_node_groups)

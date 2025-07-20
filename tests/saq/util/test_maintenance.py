import configparser

from datetime import datetime, timedelta

from saq.analysis import RootAnalysis
from saq.database import ALERT, Alert, Event, get_db
from saq.util.maintenance import distribute_old_alerts

import saq.util.maintenance

import pytest

@pytest.mark.parametrize("days,target,insert_alert,alert_age_days,add_to_event,expected_raises,upload_failure,non_success,expected_count,alert_still_exists,dry_run", [
    #days  target   insrt  age event  raise  fail   n-succ cnt isdir  dry
    (0,   "target", False, 0,  False, True,  False, False, 0,  True,  False), # invalid days
    (1,   "",       False, 0,  False, True,  False, False, 0,  True,  False), # invalid target
    (1,   "target", False, 0,  False, False, False, False, 0,  True,  False), # no alerts
    (30,  "target", True,  3,  False, False, False, False, 0,  True,  False), # alert to new to distribute
    (1,   "target", True,  3,  False, False, False, False, 1,  False, False), # alert distributed
    (1,   "target", True,  3,  True,  False, False, False, 0,  True,  False), # alert added to event
    (1,   "target", True,  3,  False, False, False, False, 1,  True,  True), # dry run
    (1,   "target", True,  3,  False, False, True,  False, 0,  True,  False), # upload failure
    (1,   "target", True,  3,  False, False, False, True,  0,  True,  False), # non-success
])
@pytest.mark.integration
def test_distribute_old_alerts(days, target, insert_alert, alert_age_days, add_to_event, expected_raises, upload_failure, non_success, expected_count, alert_still_exists, dry_run, monkeypatch, tmpdir):
    def mock_upload(*args, **kwargs):
        if upload_failure:
            raise RuntimeError("upload failure")
        if non_success:
            return { "result": False }
        else:
            return { "result": True }

    mock_config = configparser.ConfigParser()
    mock_config.read_string("""
    [global]
    node = localhost
    [api]
    api_key = key
    """)
    def mock_get_config():
        return mock_config

    import saq.util.maintenance
    monkeypatch.setattr(saq.util.maintenance, "upload", mock_upload)
    import saq.configuration
    monkeypatch.setattr(saq.configuration, "get_config", mock_get_config)

    if insert_alert:
        storage_dir = tmpdir / "alert"
        storage_dir.mkdir()

        root = RootAnalysis(
            storage_dir=str(storage_dir),
            tool="test",
            tool_instance="test",
            alert_type="test",
        )
        root.initialize_storage()
        root.save()
        ALERT(root)

        alert = get_db().query(Alert).filter(Alert.uuid==root.uuid).one()
        alert.insert_date = datetime.now() - timedelta(days=alert_age_days)
        get_db().add(alert)
        get_db().commit()

        # blech
        from saq.database import EventStatus, EventRemediation, EventVector, EventRiskLevel, EventPreventionTool, EventType, EventMapping
        event_status = EventStatus(value="test")
        event_remediation = EventRemediation(value="test")
        event_vector = EventVector(value="test")
        event_risk_level = EventRiskLevel(value="test")
        event_prevention_tool = EventPreventionTool(value="test")
        event_type = EventType(value="test")

        if add_to_event:
            event = Event(
                name="test",
                status=event_status,
                remediation=event_remediation,
                vector=event_vector,
                risk_level=event_risk_level,
                prevention_tool=event_prevention_tool,
                type=event_type,
                creation_date=datetime.now(),
            )
            get_db().add(event)
            get_db().commit()

            alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
            event = get_db().query(Event).filter(Event.name == "test").one()

            mapping = EventMapping(alert_id=alert.id, event_id=event.id)
            get_db().add(mapping)
            get_db().commit()

    if expected_raises:
        with pytest.raises(AssertionError):
            assert distribute_old_alerts(days, dry_run, target) == expected_count
    else:
        assert distribute_old_alerts(days, dry_run, target) == expected_count

    if insert_alert:
        assert storage_dir.isdir() == alert_still_exists

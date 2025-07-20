import pytest
from saq.constants import G_AUTOMATION_USER_ID
from saq.database import Remediation, get_db_connection, User, Alert, Observable
from saq.email_archive import archive_email
from saq.environment import g_int
from saq.remediation import *
from saq.observables import FQDNObservable, URLObservable

@pytest.mark.parametrize('processing, state, css, restore_key, history', [
    (False, 'new', '', None, []),
    (True, 'new', '', None,
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = None,
            ),
        ],
    ),
    (True, 'removing', 'warning', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True, user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_IN_PROGRESS,
            ),
        ],
    ),
    (True, 'removing', 'danger', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = False,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_IN_PROGRESS,
            ),
        ],
    ),
    (False, 'removed', 'success', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'remove failed', 'danger', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = False,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'restored', 'success', 'hello',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
            Remediation(
                action = REMEDIATION_ACTION_RESTORE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = None,
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
    (False, 'restored', 'success', 'world',
        [
            Remediation(
                action = REMEDIATION_ACTION_REMOVE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'hello',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
            Remediation(
                action = REMEDIATION_ACTION_RESTORE,
                type = 'email',
                key = '<test@test.com>|jdoe@site.com',
                successful = True,
                user_id = 1,
                restore_key = 'world',
                status = REMEDIATION_STATUS_COMPLETED,
            ),
        ],
    ),
])
@pytest.mark.integration
def test_remediation_target(processing, state, css, restore_key, history):
    # add all remediation history
    for remediation in history:
        remediation.user_id = g_int(G_AUTOMATION_USER_ID)
        get_db().add(remediation)
    get_db().commit()

    # instantiate a remediation target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')

    # validate target properties
    assert target.processing == processing
    assert target.state == state
    assert target.css_class == css
    assert target.last_restore_key == restore_key

@pytest.mark.integration
def test_remediation_target_id():
    # instantiate a target from the id of another and ensure they are the same target
    target1 = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    target2 = RemediationTarget(id=target1.id)
    assert target2.type == target1.type
    assert target2.value == target1.value
    assert target2.id == target1.id

@pytest.mark.integration
def test_remediation_target_queue():
    # fetch targets with Remediation service
    service = RemediationService()
    targets = service.get_targets()
    assert len(targets) == 0

    # queue a remediation of a target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    target.queue(REMEDIATION_ACTION_REMOVE, g_int(G_AUTOMATION_USER_ID))

    # fetch targets with Remediation service
    targets = service.get_targets()
    assert len(targets) == 1
    assert targets[0].type == target.type
    assert targets[0].key == target.value
    assert targets[0].restore_key is None
    assert targets[0].user_id == g_int(G_AUTOMATION_USER_ID)
    assert targets[0].action == REMEDIATION_ACTION_REMOVE
    assert targets[0].status == REMEDIATION_STATUS_IN_PROGRESS
    assert targets[0].successful
    assert targets[0].lock == service.uuid
    assert targets[0].lock_time is not None

@pytest.mark.integration
def test_remediation_target_stop_remediation():
    # queue a target for removal
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    target.queue(REMEDIATION_ACTION_REMOVE, g_int(G_AUTOMATION_USER_ID))
    
    # reload target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    
    # make sure the target was queued
    assert len(target.history) == 1
    assert target.history[0].status == 'NEW'
    
    # stop all remediations for the target
    target.stop_remediation()
    
    # reload target
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    assert target.history[0].status == 'COMPLETED'
    assert target.history[0].successful == False

class MockRemediator(Remediator):
    def __init__(self, config_section_name, result):        
        self.name = config_section_name
        self.config = {}
        self.result = result

    @property
    def type(self): 
        return 'email'

    def remove(self, target):
        return self.result

@pytest.mark.parametrize('result1, result2, status, success, restore_key', [
    (RemediationSuccess('hello', restore_key='test'), RemediationSuccess('world'), REMEDIATION_STATUS_COMPLETED, True, 'test'),
    (RemediationSuccess('hello'), RemediationSuccess('world'), REMEDIATION_STATUS_COMPLETED, True, None),
    (RemediationSuccess('hello'), RemediationDelay('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationSuccess('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationSuccess('hello'), RemediationFailure('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationSuccess('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, True, None),
    (RemediationDelay('hello'), RemediationDelay('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationDelay('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationDelay('hello'), RemediationFailure('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationDelay('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_IN_PROGRESS, True, None),
    (RemediationError('hello'), RemediationError('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationError('hello'), RemediationFailure('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationError('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_IN_PROGRESS, False, None),
    (RemediationFailure('hello'), RemediationFailure('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationFailure('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, False, None),
    (RemediationIgnore('hello'), RemediationIgnore('world'), REMEDIATION_STATUS_COMPLETED, False, None),
])
@pytest.mark.integration
def test_remediation(result1, result2, status, success, restore_key):
    # setup a test remediation service
    service = RemediationService()
    service.remediators.append(MockRemediator('test1', result1))
    service.remediators.append(MockRemediator('test2', result2))

    # queue target
    RemediationTarget('email', '<test@test.com>|jdoe@site.com').queue(REMEDIATION_ACTION_REMOVE, g_int(G_AUTOMATION_USER_ID))

    # remediate target with remediation service
    target = service.get_targets()[0]
    service.remediate(target)

    # verify results
    target = RemediationTarget('email', '<test@test.com>|jdoe@site.com')
    assert target.history[0].status == status
    assert target.history[0].successful == success
    assert target.history[0].restore_key == restore_key

TEST_MESSAGE_ID = "<test@test.com>"
TEST_RECIPIENTS = ["foo@company.com", "john@company.com", "jane@company.com"]

@pytest.fixture
def archived_email(tmpdir):
    email = tmpdir / "email"
    email.write_binary(b"test")

    return archive_email(str(email), TEST_MESSAGE_ID, TEST_RECIPIENTS)

# this is an integration test because I don't have a way to mock the email_archive database
@pytest.mark.integration
def test_message_id_remediation_targets(archived_email):
    from saq.observables import MessageIDObservable

    # add some remediation history
    history = Remediation(type='email', key="<test@test.com>|foo@company.com", action='remove', user_id=g_int(G_AUTOMATION_USER_ID))
    get_db().add(history)
    get_db().commit()

    # get remediation targets for MessageIDObservable
    message_id = MessageIDObservable("<test@test.com>")
    targets = message_id.remediation_targets
    assert len(targets) == 3
    target_strings = []
    for target in targets:
        target_strings.append(f"{target.type}|{target.value}")

    assert 'email|<test@test.com>|foo@company.com' in target_strings
    assert 'email|<test@test.com>|john@company.com' in target_strings
    assert 'email|<test@test.com>|jane@company.com' in target_strings


@pytest.mark.integration
def test_url_remediation_targets():
    observable = URLObservable(value="http://www.company.com")
    assert not observable.remediation_targets


@pytest.mark.integration
def test_fqdn_remediation_targets():
    observable = FQDNObservable(value="company.com")
    assert not observable.remediation_targets


# make sure an observable with a bad value does not trip up the get_remediation_targets function
@pytest.mark.integration
def test_alert_get_remediation_targets_bad_observable(monkeypatch):
    class MockAlert(Alert):
        def __init__(self):
            pass
        def get_observables(self):
            return [Observable(type='ipv4', md5='123', value=b'123')]

    alert = MockAlert()
    targets = alert.get_remediation_targets()

    assert targets == []

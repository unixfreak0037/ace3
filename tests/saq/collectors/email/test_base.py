
import datetime

import pytest

from saq.collectors.email import base


class MockFunctions:
    def __init__(self):
        self.set_unmatched = False
    def set_unmatched_local_directory(self):
        self.set_unmatched = True


@pytest.mark.unit
def test_email_user_class():
    """Simple test to make sure email_address attribute is correct."""
    # setup
    expected = 'my-email@nunya.local'
    email_user = base.EmailUser(expected)
    # verify
    assert expected == email_user.email_address


@pytest.mark.parametrize('config_key,config_value,property_name,expected_value', [
    ('analysis_mode', 'something_else', 'analysis_mode', 'something_else'),
    ('analysis_mode', None, 'analysis_mode', 'email'),
])
@pytest.mark.unit
def test_email_processors_load_from_config_base_config_items(base_config, email_collection_processor, config_key, config_value, property_name, expected_value):
    """This test makes sure any subclass of the abstract class EmailCollectionBaseProcessor
    correctly implements the configuration for the base class or at least calls the base
    classes `load_from_config`.

    email_collection_processor is parameterized with all subclasses of EmailCollectionbaseProcessor
    that can be found within the submodules of `saq.collectors.email`."""

    mock = MockFunctions()
    processor_class = email_collection_processor
    processor = processor_class(mock)
    processor.set_unmatched_local_directory = mock.set_unmatched_local_directory
    section = 'email_collector_blah'

    config = base_config
    if config_value is None and config_key in config['email_collector_blah']:
        del config['email_collector_blah'][config_key]

    if config_value is not None:
        config['email_collector_blah'][config_key] = config_value

    processor.load_from_config(section, config=config)

    assert processor.target_mailbox == 'simple@kindof.man'
    assert processor.frequency == 10
    assert processor.delete_emails
    assert processor.save_unmatched_remotely
    assert processor.save_unmatched_locally
    assert processor.always_alert
    assert processor.add_email_to_alert
    assert processor.alert_prefix == 'FREEBIRD'
    assert processor.folders == ['sweet', 'home', 'alabama']
    assert processor.unmatched_folder == 'Skynyrd'
    assert mock.set_unmatched
    assert processor.section == section
    assert processor._persistence_source_key == f'remote_email_collector:simple@kindof.man'

    assert getattr(processor, property_name) == expected_value


@pytest.mark.unit
def test_email_processors_failure_to_set_process_email_func(email_collection_processor):
    """Validate exception raised if process_email_func was not set with a callable."""
    processor = email_collection_processor(MockFunctions())

    with pytest.raises(ValueError):
        processor.process_email()


@pytest.mark.unit
def test_email_processors_succesfully_set_process_email(email_collection_processor):
    """Validate exception not raised if process_email_func was set with a callable."""
    processor = email_collection_processor(MockFunctions())
    processor.process_email_func = lambda *args, **kwargs: True
    assert processor.process_email()

class TestFailureMockFunctions:
    def _execute(self, **kwargs):
        raise RuntimeError("CAPTURE MARKER")

@pytest.mark.unit
def test_concurrent_failure_logging(caplog, email_collection_processor):
    mock = TestFailureMockFunctions()
    processor = email_collection_processor(mock)
    processor._execute = mock._execute

    # starts at 0 and the default limit is 30 so initially these log as warnings
    assert processor.concurrent_failure_count == 0
    processor.attempt_execution()
    found_log_message = False
    for record in caplog.records:
        if record.levelname == 'WARNING' and 'CAPTURE MARKER' in record.message:
            found_log_message = True
            break

    assert found_log_message
    assert processor.concurrent_failure_count == 1

    # switch the limit to 1 and fail again and then it logs as error
    processor.concurrent_failure_count_limit = 1
    processor.attempt_execution()
    found_log_message = False
    for record in caplog.records:
        if record.levelname == 'ERROR' and 'CAPTURE MARKER' in record.message:
            found_log_message = True
            break

    assert found_log_message
    assert processor.concurrent_failure_count == 2


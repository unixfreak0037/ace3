import pytest

from tests.saq.collectors.email.conftest import SECTION, Stub, TO_RECIPIENT_STRINGS, BCC_RECIPIENT_STRINGS, CC_RECIPIENT_STRINGS, MIME_CONTENT, MIME_CONTENT_NO_BYTES
from saq.collectors.email.imap import IMAPEmailObject, IMAPEmailCollectionProcessor


@pytest.fixture(scope='function')
def imap_email_object(mock_email, email_kwargs):
    from email import message_from_bytes

    mock_message = message_from_bytes(MIME_CONTENT)
    yield IMAPEmailObject(mock_message, MIME_CONTENT)


@pytest.mark.unit
def test_imap_email_object(imap_email_object, email_kwargs):
    """Test the imap Email object."""

    email = imap_email_object

    assert email._obj_type == 'imap'
    assert email.sender
    assert email.subject == email_kwargs['subject']
    assert email.datetime_received == email_kwargs['datetime_received']
    assert email.id == email_kwargs['message_id']
    assert email.message_id == email_kwargs['message_id']
    assert email.mime_content == MIME_CONTENT
    to_recipients = [recipient.email_address for recipient in email.to_recipients]
    cc_recipients = [recipient.email_address for recipient in email.cc_recipients]
    bcc_recipients = [recipient.email_address for recipient in email.bcc_recipients]
    assert to_recipients == TO_RECIPIENT_STRINGS
    assert cc_recipients == CC_RECIPIENT_STRINGS
    assert bcc_recipients == BCC_RECIPIENT_STRINGS


@pytest.mark.unit
def test_imap_processor_load_config(imap_config):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)

    assert processor.server == imap_config[SECTION]['server']
    assert processor.server_port == int(imap_config[SECTION]['server_port'])
    assert processor.target_mailbox == imap_config[SECTION]['target_mailbox']
    assert processor.password == imap_config[SECTION]['password']


@pytest.mark.unit
def test_imap_processor_initialize_auth_missing_password_prevent_password_lockout(imap_config, caplog):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    processor.password = None

    assert not processor.initialize_auth()
    assert f'initializing imap auth for {SECTION}' in caplog.text


class MockIMAPClassBase:
    def __init__(self, server=None):
        self.server = server


class MockIMAPSuccessful(MockIMAPClassBase):
    @staticmethod
    def _success():
        return 'OK', 'Success'

    def login(self, *args, **kwargs):
        return self._success()

    def select(self, *args, **kwargs):
        return self._success()

    @staticmethod
    def search(*args, **kwargs):
        return 'OK', ['1 2 3 4']

    @staticmethod
    def fetch(*args, **kwargs):
        return 'OK', [(b'(', MIME_CONTENT)]


class MockIMAPNoBytes(MockIMAPClassBase):
    @staticmethod
    def _success():
        return 'OK', 'Success'

    def login(self, *args, **kwargs):
        return self._success()

    def select(self, *args, **kwargs):
        return self._success()

    @staticmethod
    def search(*args, **kwargs):
        return 'OK', ['1 2 3 4']

    @staticmethod
    def fetch(*args, **kwargs):
        return 'OK', [(b'(', MIME_CONTENT_NO_BYTES)]


class MockIMAPFailure(MockIMAPClassBase):
    @staticmethod
    def _failed():
        return '403', 'Failed'

    def login(self, *args, **kwargs):
        return self._failed()

    def select(self, *args, **kwargs):
        return self._failed()

    def search(self, *args, **kwargs):
        return self._failed()

    def fetch(self, *args, **kwargs):
        return self._failed()


@pytest.mark.unit
def test_imap_processor_initialize_auth_account_success(imap_config):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)

    assert processor.initialize_auth(imap_class=MockIMAPSuccessful)
    assert processor.mail


@pytest.mark.unit
def test_imap_processor_initialize_auth_failed(imap_config, caplog):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)

    assert not processor.initialize_auth(imap_class=MockIMAPFailure)
    assert f'Unable to initialize imap authentication for ' in caplog.text

@pytest.mark.unit
def test_imap_processor_select_folder_success(imap_config):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    processor.mail = MockIMAPSuccessful()

    assert processor.select_folder('inbox')


@pytest.mark.unit
def test_imap_processor_select_folder_failed(imap_config, caplog):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    processor.mail = MockIMAPFailure()

    assert not processor.select_folder('inbox')
    assert f"Unable to select folder 'inbox' in" in caplog.text


@pytest.mark.unit
def test_imap_processor_get_all_message_ids_success(imap_config):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    processor.mail = MockIMAPSuccessful()

    assert processor.get_all_message_ids() == ['1', '2', '3', '4']


@pytest.mark.unit
def test_imap_processor_get_all_message_ids_failed(imap_config, caplog):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    processor.mail = MockIMAPFailure()

    assert processor.get_all_message_ids() == []
    assert f"Unable to get message IDs" in caplog.text


@pytest.mark.unit
def test_imap_processor_get_message_content_success(imap_config):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    processor.mail = MockIMAPSuccessful()

    assert processor.get_message_content('1') == MIME_CONTENT


@pytest.mark.unit
def test_imap_processor_get_message_content_failed(imap_config, caplog):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    processor.mail = MockIMAPFailure()

    assert processor.get_message_content('1') is None
    assert f"Unable to get message 1 from" in caplog.text


@pytest.mark.integration
def test_imap_processor_execute_success(imap_config, caplog):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    assert processor._execute(imap_class=MockIMAPSuccessful)
    assert f"target@mailbox.com:sweet' metrics - total: 4, already processed: 0, unmatched: 0, errors: 4" in caplog.text
    assert f"target@mailbox.com:home' metrics - total: 4, already processed: 0, unmatched: 0, errors: 4" in caplog.text
    assert f"target@mailbox.com:alabama' metrics - total: 4, already processed: 0, unmatched: 0, errors: 4" in caplog.text


@pytest.mark.integration
def test_imap_processor_execute_no_bytes(imap_config, caplog):
    processor = IMAPEmailCollectionProcessor(Stub())
    processor.load_from_config(SECTION, config=imap_config)
    assert processor._execute(imap_class=MockIMAPNoBytes) is False
    assert "Fetching 1 did not return bytes. response_data:" in caplog.text


@pytest.mark.unit
def test_imap_delete(imap_config, caplog):
    class MockMail:
        deleted = False
        def store(self, message_id, command, flags):
            self.message_id = message_id
            self.command = command
            self.flags = flags
        def expunge(self):
            self.deleted = True

    mail = MockMail()
    class MockProcessor(IMAPEmailCollectionProcessor):
        def __init__(self):
            self.mail = mail

    # run
    processor = MockProcessor()
    processor.handle_delete_message('123')
    processor.handle_expunge()

    # verify
    assert mail.message_id == '123'
    assert mail.command == '+FLAGS'
    assert mail.flags == '\\Deleted'
    assert mail.deleted == True

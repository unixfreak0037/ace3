
from abc import ABC
import configparser
from datetime import datetime, timezone, timedelta
import importlib
import inspect
import pkgutil
from types import ModuleType
from typing import Union, Type

import pytest

from saq.collectors.email.base import EmailCollectionBaseProcessor, EmailObject

def test_module(module_name: str) -> Union[ModuleType, None]:
    """Return module if it exists."""
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError:
        return None

def harvest_modules(starting_module_name: str) -> set:
    """Return set of modules found within the module/package hierarchy."""
    module_set = set()
    if (module_obj := test_module(starting_module_name)) is not None:
        module_set.add(module_obj)
    try:
        # If it quacks like a package (it has __path__), then we'll walk it for modules like a package
        for _, name, _ in pkgutil.walk_packages(module_obj.__path__):
            # Explicitly build the module name, so that we don't accidentally
            # add modules that resolve to some package outside of our
            # current package hierarchy.
            sub_module_name = f'{starting_module_name}.{name}'
            module_set |= harvest_modules(sub_module_name)
    except AttributeError:
        # no quacks given
        pass
    return module_set

def find_classes(starting_module: str, abstract_class: Type[ABC]) -> dict:
    """Search out and add all classes that are subclasses
    of a base abstract class. You can use this to populate
    test parametrization, to ensure classes that inherit an
    abstract class are implementing the base class features
    correctly."""
    class_map = {}
    sub_modules = harvest_modules(starting_module)
    for module in sub_modules:
        for _, value in inspect.getmembers(module, predicate=inspect.isclass):
            # If it's not a subclass of the class we want to test, then we don't care
            if not issubclass(value, abstract_class):
                continue
            # We want to check actual subclasses, not the abstract class itself
            if value == abstract_class:
                continue
            class_name = value.__name__
            class_path = f'{value.__module__}.{class_name}'
            class_map[class_path] = getattr(module, class_name)
    return class_map

SECTION = 'email_collector_blah'
TARGET_MAILBOX = 'simple@kindof.man'
UNMATCHED_FOLDER = 'Skynyrd'
ALERT_PREFIX = 'FREEBIRD'
SWITCHBOARD_SECTION = 'switchboard_test'

BASE_CONFIG = f"""
[{SECTION}]
target_mailbox = {TARGET_MAILBOX}
frequency = 10
delete_emails = yes
save_unmatched_remotely = yes
save_unmatched_locally = yes
always_alert = yes
analysis_mode = something_else
add_email_to_alert = yes
alert_prefix = {ALERT_PREFIX}
folder_0 = sweet
folder_1 = home
folder_2 = alabama
unmatched_folder = {UNMATCHED_FOLDER}
switchboard_map = {SWITCHBOARD_SECTION}

[{SWITCHBOARD_SECTION}]
source_type_1 = sender
source_values_1 = test-sender@local.local
module_1 = saq.collectors.site.test_module
class_1 = TestEmailParser
arg_test_1 = my_test_arg_value

source_type_2 = sender
source_values_2 = test-sender2@local.local
module_2 = saq.collectors.site.test_module2
class_2 = TestEmailParser2
arg_my_test_argument_ = my_test_arg_value

source_type_3 = sender
source_values_3 = test-sender2@local.local
module_3 = saq.collectors.site.test_module2
class_3 = TestEmailParser2
"""


@pytest.fixture(scope='function')
def base_config():
    config = configparser.ConfigParser()
    config.read_string(BASE_CONFIG)
    yield config


@pytest.fixture(scope='function')
def ews_config():
    config = configparser.ConfigParser()
    config.read_string(BASE_CONFIG)
    config[SECTION]['username'] = 'username'
    config[SECTION]['password'] = 'my_password'
    config[SECTION]['server'] = 'my_server'
    config[SECTION]['page_size'] = '10'
    config[SECTION]['processor_type'] = 'ews'
    yield config


@pytest.fixture(scope='function')
def graph_config():
    config = configparser.ConfigParser()
    config.read_string(BASE_CONFIG)
    config[SECTION]['processor_type'] = 'graph'
    yield config


@pytest.fixture(scope='function')
def imap_config():
    config = configparser.ConfigParser()
    config.read_string(BASE_CONFIG)
    config[SECTION]['server'] = 'my_server'
    config[SECTION]['server_port'] = '1234'
    config[SECTION]['target_mailbox'] = 'target@mailbox.com'
    config[SECTION]['password'] = 'password'
    yield config


# Parametrize email stuff based on abstract classes
EMAIL_PROCESSORS = find_classes('saq.collectors.email', EmailCollectionBaseProcessor)
EMAIL_OBJECTS = find_classes('saq.collectors.email', EmailObject)


def pytest_generate_tests(metafunc):
    if 'email_collection_processor' in metafunc.fixturenames:
        metafunc.parametrize('email_collection_processor', list(EMAIL_PROCESSORS.keys()), indirect=True)
    if 'email_object' in metafunc.fixturenames:
        metafunc.parametrize('email_object', list(EMAIL_OBJECTS.keys()), indirect=True)


@pytest.fixture(scope='module')
def email_collection_processor(request):
    if (processor := EMAIL_PROCESSORS.get(request.param, None)) is not None:
        return processor
    raise ValueError("invalid email collection processor config")


@pytest.fixture(scope='module')
def email_object(request):
    if (email_obj := EMAIL_OBJECTS.get(request.param, None)) is not None:
        return email_obj
    raise ValueError('invalid email object test config')


# Test helpers
@pytest.fixture(scope='function')
def mailbox_mock():
    class MailboxMock:
        def __init__(self, email_address):
            self.email_address = email_address
            self.map = {'emailAddress': {'address': email_address}}  # for testing graph api

        def __getitem__(self, value):
            return self.map[value]
    yield MailboxMock


@pytest.fixture(scope='function')
def mock_email(mailbox_mock):
    class MockEmail:
        def __init__(self, text, **kwargs):
            self.text = text
            _email_address = kwargs.get('sender') or "ima_sender@gmail.com"
            _mailbox_class = kwargs.get('mailbox_class') or mailbox_mock
            self._to_recipients = kwargs.get('to_recipients') or []
            self._cc_recipients = kwargs.get('cc_recipients') or []
            self._bcc_recipients = kwargs.get('bcc_recipients') or []
            self._delete = kwargs.get('delete') or True
            self._delete_called = False
            self._move = kwargs.get('move') or True
            self._move_called = False
            self._copy = kwargs.get('copy') or True
            self._copy_called = False
            self.mailbox = _mailbox_class(_email_address)
            self.kwargs = kwargs

        @property
        def mime_content(self):
            return self.text

        @property
        def datetime_received(self):
            return self.kwargs.get('datetime_received') or datetime.now()

        @property
        def subject(self):
            return self.kwargs.get('subject') or "my_subject_line"

        @property
        def id(self):
            return self.kwargs.get('id')

        @property
        def message_id(self):
            return self.kwargs.get('message_id') or "some_fake_email_id2@email.com"

        @property
        def sender(self):
            return self.mailbox

        @property
        def body(self):
            return self.kwargs.get('body') or self.text

        def delete(self):
            self._delete_called = True
            return self._delete

        def move(self, *args, **kwargs):
            self._move_called = True
            return self._move

        def copy(self, *args, **kwargs):
            self._copy_called = True
            return self._copy

        @property
        def to_recipients(self):
            return self._to_recipients

        @property
        def cc_recipients(self):
            return self._cc_recipients

        @property
        def bcc_recipients(self):
            return self._bcc_recipients

    yield MockEmail


SECTION = 'email_collector_blah'


class Stub:
    def __init__(self):
        pass

    @property
    def is_service_shutdown(self):
        return False


TO_RECIPIENT_STRINGS = ['recipient1@local.local']
CC_RECIPIENT_STRINGS = ['recipient2@local.local']
BCC_RECIPIENT_STRINGS = ['recipient3@local.local']
RECIPIENT_STRINGS = ['recipient1@local.local', 'recipient2@local.local', 'recipient3@local.local']
MIME_CONTENT = b"""Return-Path: test-sender@local.local
MIME-Version: 1.0
From: test-sender@local.local
Subject: need your password to unlock your next level
Date: Fri, 9 Jul 2021 14:20:20 -0400
Message-ID: <some_fake_message_id@local.local>
To: recipient1@local.local
Cc: recipient2@local.local
Bcc: recipient3@local.local

<html><body><div><b>i hate html</b></div></body></html>
"""
MIME_CONTENT_NO_BYTES = "Whoops"
KWARGS = {
        'sender': 'test-sender@local.local',
        'datetime_received': datetime(2021, 7, 9, 14, 20, 20,
                                      tzinfo=timezone(timedelta(days=-1, seconds=72000))),
        'subject': 'need your password to unlock your next level',
        'id': 'weripotupeorituwperoitu',
        'message_id': '<some_fake_message_id@local.local>',
        'body': '<html><body><div><b>i hate html</b></div></body></html>',
}


@pytest.fixture(scope='function')
def recipient_objects(mailbox_mock):
    yield [mailbox_mock(recipient) for recipient in RECIPIENT_STRINGS]


@pytest.fixture(scope='function')
def email_kwargs(recipient_objects):
    yield {
        **KWARGS,
        'to_recipients': [recipient for recipient in recipient_objects],
        'cc_recipients': [recipient for recipient in recipient_objects],
        'bcc_recipients': [recipient for recipient in recipient_objects],
    }

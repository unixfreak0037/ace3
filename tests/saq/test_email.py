import pytest

from saq.email import decode_rfc2822, is_local_email_domain, normalize_email_address, normalize_message_id

@pytest.mark.parametrize('email_address, expected_result', [
    ('test@localdomain', True),
    ('test@host.localdomain', True),
    ('test@otherdomain', False),
    ('"Test User" <test@localdomain>', True),
    ('"Test User" <test@localdoman>', False)])
@pytest.mark.integration
def test_is_local_email_domain(email_address, expected_result):
    assert is_local_email_domain(email_address) == expected_result

@pytest.mark.parametrize("source, target", [
    ('test@user.com', 'test@user.com'),
    ('<test@user.com>', 'test@user.com'),
    ('<TEST@USER.COM>', 'test@user.com'),
    ('"user name" <TEST@USER.COM>', 'test@user.com'),
    ('user name <TEST@USER.COM>', 'test@user.com'),
])
@pytest.mark.unit
def test_normalize_email_address(source: str, target: str):
    assert normalize_email_address(source) == target

@pytest.mark.parametrize("source, target", [
    ('=?utf-8?B?UmU6IFVyZ2VudA==?=', 'Re: Urgent'),
    ('=?UTF-8?B?RklOQUwgREFZIC0gRU1BSUwgRVhDTFVTSVZFIC0gJDMyLjk5IEp1?= =?UTF-8?B?c3QgQmFzaWNz4oSiIDEwLVJlYW0gQ2FzZSBQYXBlcg==?=', 
                        'FINAL DAY - EMAIL EXCLUSIVE - $32.99 Just Basics™ 10-Ream Case Paper'),
    ('=?US-ASCII?Q?CSMS#_19-000228_-_ACE_CERTIFICATION_Scheduled_Ma?= =?US-ASCII?Q?intenance,_Wed._May_1,_2019_@_1700_ET_to_2000_ET?=', 
                        'CSMS# 19-000228 - ACE CERTIFICATION Scheduled Maintenance, Wed. May 1, 2019 @ 1700 ET to 2000 ET'),
    ('=?Windows-1252?Q?Money_Talk_=96_Profit=99_Performance_Monitor_(Honeywell_?= =?Windows-1252?Q?Webinar)?=', 
                        'Money Talk – Profit™ Performance Monitor (Honeywell Webinar)'),
    ('=?ISO-8859-1?Q?Puede_que_algunos_contribuyentes_tengan_?= =?ISO-8859-1?Q?que_enmendar_su_declaraci=F3n_de_impuestos?=', 
                        'Puede que algunos contribuyentes tengan que enmendar su declaración de impuestos'),
    ('=?GBK?B?UmU6gYbKssC8tcTNxo9Wst/C1A==?=', 
                        'Re:亞什兰的推廣策略'),
])
@pytest.mark.unit
def test_decode_rfc2822(source: str, target: str):
    assert decode_rfc2822(source) == target

# TODO - move check_message_id to shared location as well as the tests for it.
@pytest.mark.parametrize("message_id", [
    'this_is_fake@local.local',
    '<this_is_fake@local.local',
    'this_is_fake@local.local>',
    ' this_is_fake@local.local>\n',
])
@pytest.mark.unit
def test_normalize_message_id_no_brackets(message_id):
    assert normalize_message_id(message_id) == "<this_is_fake@local.local>"
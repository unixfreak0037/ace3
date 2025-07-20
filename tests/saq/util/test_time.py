import pytest

from saq.environment import get_local_timezone
from saq.util.time import parse_event_time

@pytest.mark.unit
def test_util_000_date_parsing():
    default_format = '2018-10-19 14:06:34 +0000'
    old_default_format = '2018-10-19 14:06:34'
    json_format = '2018-10-19T18:08:08.346118-05:00'
    old_json_format = '2018-10-19T18:08:08.346118'
    splunk_format = '2015-02-19T09:50:49.000-05:00'

    result = parse_event_time(default_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 14
    assert result.minute == 6
    assert result.second == 34
    assert result.tzinfo
    assert int(result.tzinfo.utcoffset(None).total_seconds()) == 0

    result = parse_event_time(old_default_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 14
    assert result.minute == 6
    assert result.second == 34
    assert result.tzinfo
    assert get_local_timezone().tzname == result.tzinfo.tzname
    
    result = parse_event_time(json_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 18
    assert result.minute == 8
    assert result.second == 8
    assert result.tzinfo
    assert int(result.tzinfo.utcoffset(None).total_seconds()) == -(5 * 60 * 60)

    result = parse_event_time(old_json_format)
    assert result.year == 2018
    assert result.month == 10
    assert result.day == 19
    assert result.hour == 18
    assert result.minute == 8
    assert result.second == 8
    assert result.tzinfo
    assert get_local_timezone().tzname == result.tzinfo.tzname

    result = parse_event_time(splunk_format)
    assert result.year == 2015
    assert result.month == 2
    assert result.day == 19
    assert result.hour == 9
    assert result.minute == 50
    assert result.second == 49
    assert result.tzinfo
    assert int(result.tzinfo.utcoffset(None).total_seconds()), -(5 * 60 * 60)
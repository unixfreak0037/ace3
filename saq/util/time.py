from datetime import datetime, timedelta
import logging
import re

import pytz

from saq.constants import EVENT_TIME_FORMAT, EVENT_TIME_FORMAT_JSON, EVENT_TIME_FORMAT_JSON_TZ, EVENT_TIME_FORMAT_TZ, G_LOCAL_TIMEZONE
from saq.environment import g, get_local_timezone


def create_timedelta(timespec):
    """Utility function to translate DD:HH:MM:SS into a timedelta object."""
    duration = timespec.split(':')
    seconds = int(duration[-1])
    minutes = 0
    hours = 0
    days = 0

    if len(duration) > 1:
        minutes = int(duration[-2])
    if len(duration) > 2:
        hours = int(duration[-3])
    if len(duration) > 3:
        days = int(duration[-4])

    return timedelta(days=days, seconds=seconds, minutes=minutes, hours=hours)

RE_ET_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}$')
RE_ET_OLD_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$')
RE_ET_JSON_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,6}[+-][0-9]{4}$')
RE_ET_OLD_JSON_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,6}$')
RE_ET_ISO_FORMAT = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3,6}[+-][0-9]{2}:[0-9]{2}$')

def parse_event_time(event_time):
    """Return the datetime object for the given event_time."""
    # remove any leading or trailing whitespace
    event_time = event_time.strip()

    if RE_ET_FORMAT.match(event_time):
        return datetime.strptime(event_time, EVENT_TIME_FORMAT_TZ)
    elif RE_ET_OLD_FORMAT.match(event_time):
        return get_local_timezone().localize(datetime.strptime(event_time, EVENT_TIME_FORMAT))
    elif RE_ET_JSON_FORMAT.match(event_time):
        return datetime.strptime(event_time, EVENT_TIME_FORMAT_JSON_TZ)
    elif RE_ET_ISO_FORMAT.match(event_time):
        # we just need to remove the : in the timezone specifier
        # this has been fixed in python 3.7
        event_time = event_time[:event_time.rfind(':')] + event_time[event_time.rfind(':') + 1:]
        return datetime.strptime(event_time, EVENT_TIME_FORMAT_JSON_TZ)
    elif RE_ET_OLD_JSON_FORMAT.match(event_time):
        return g(G_LOCAL_TIMEZONE).localize(datetime.strptime(event_time, EVENT_TIME_FORMAT_JSON))
    else:
        raise ValueError("invalid date format {}".format(event_time))

def local_time():
    """Returns datetime.now() in UTC time zone."""
    return g(G_LOCAL_TIMEZONE).localize(datetime.now()).astimezone(pytz.UTC)

def format_iso8601(d):
    """Given datetime d, return an iso 8601 formatted string YYYY-MM-DDTHH:mm:ss.fff-zz:zz"""
    assert isinstance(d, datetime)
    d, f, z = d.strftime('%Y-%m-%dT%H:%M:%S %f %z').split()
    return f'{d}.{f[:3]}-{z[1:3]}:{z[3:]}'

def validate_time_format(t):
    """Returns True if the given string matches the event time format, False otherwise."""
    try:
        datetime.strptime(t, EVENT_TIME_FORMAT)
    except ValueError as e:
        logging.error("invalid event time format {0}: {1}".format(t, str(e)))
        return False

    return True

def splunktime_to_datetime(splunk_time):
    """Convert a splunk time in 2015-02-19T09:50:49.000-05:00 format to a datetime object."""
    assert isinstance(splunk_time, str)
    #return datetime.datetime.strptime(splunk_time.split('.')[0], '%Y-%m-%dT%H:%M:%S')
    return parse_event_time(splunk_time)

def splunktime_to_saqtime(splunk_time):
    """Convert a splunk time in 2015-02-19T09:50:49.000-05:00 format to SAQ time format YYYY-MM-DD HH:MM:SS."""
    assert isinstance(splunk_time, str)
    return parse_event_time(splunk_time).strftime(EVENT_TIME_FORMAT_JSON_TZ)
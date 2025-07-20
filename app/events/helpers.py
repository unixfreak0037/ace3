import os

import saq
from saq.error import report_exception

#from flask import url_for
def url_for(path, direct=None, _external=True):
    return saq.CONFIG['tip']['event_url_pattern'].format(direct=direct)

from saq.database import refresh_observable_expires_on, Event, MalwareMapping


def event_closing_tasks(event_id: str):
    def _write_error_to_logfile(point_of_failure: str, exception):
        exception_file = report_exception()
        with open(os.path.join(saq.CONFIG['global']['data_dir'], 'var', f'event_creation_{event_id}.failed'), 'a') as f:
            f.write(f'Error occurred while {point_of_failure}\n\n')
            f.write(f'{exception}\n\n')
            f.write(f'Error Report: {exception_file}\n\n')

    event = saq.db.query(Event).filter(Event.id == event_id).one()
    _nullify_expires_on_if_threat_actor(event)

def _nullify_expires_on_if_threat_actor(event: Event):
    if event.campaign:
        if saq.CONFIG['observable_expiration_mappings'].getboolean('never_expire_with_threat_actor', fallback=False):
            refresh_observable_expires_on(event.alerts, nullify=True)

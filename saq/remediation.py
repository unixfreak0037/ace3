from base64 import b64encode, b64decode
from datetime import UTC, datetime, timedelta
import importlib
import json
import logging
from saq.configuration import get_config
from saq.database import Remediation, ObservableRemediationMapping, get_db
from saq.database.database_observable import upsert_observable
from saq.database.model import Alert
from saq.database.util.alert import get_alert_by_uuid
from saq.error import report_exception
from sqlalchemy import or_
import threading
import time
import uuid

from saq.observables.generator import create_observable
from saq.service import ACEServiceInterface

# remediation statuses
REMEDIATION_STATUS_NEW = 'NEW'
REMEDIATION_STATUS_IN_PROGRESS = 'IN_PROGRESS'
REMEDIATION_STATUS_COMPLETED = 'COMPLETED'

# remediator statuses
REMEDIATOR_STATUS_DELAYED = 'DELAYED'
REMEDIATOR_STATUS_ERROR = 'ERROR'
REMEDIATOR_STATUS_FAILED = 'FAILED'
REMEDIATOR_STATUS_IGNORE = 'IGNORE'
REMEDIATOR_STATUS_SUCCESS = 'SUCCESS'
COMPLETED_REMEDIATOR_STATUSES = [
    REMEDIATOR_STATUS_FAILED,
    REMEDIATOR_STATUS_IGNORE,
    REMEDIATOR_STATUS_SUCCESS,
]
SUCCESSFUL_REMEDIATOR_STATUSES = [
    REMEDIATOR_STATUS_DELAYED,
    REMEDIATOR_STATUS_SUCCESS,
]
UNSUCCESSFUL_REMEDIATOR_STATUSES = [
    REMEDIATOR_STATUS_ERROR,
    REMEDIATOR_STATUS_FAILED,
]

# remediation actions
REMEDIATION_ACTION_REMOVE = 'remove'
REMEDIATION_ACTION_RESTORE = 'restore'

def RemediationResult(status, message, restore_key=None):
    return {'status':status, 'message':message, 'restore_key':restore_key}

def RemediationDelay(message):
    return RemediationResult(REMEDIATOR_STATUS_DELAYED, message)

def RemediationError(message):
    return RemediationResult(REMEDIATOR_STATUS_ERROR, message)

def RemediationFailure(message, restore_key=None):
    return RemediationResult(REMEDIATOR_STATUS_FAILED, message, restore_key=restore_key)

def RemediationIgnore(message):
    return RemediationResult(REMEDIATOR_STATUS_IGNORE, message)

def RemediationSuccess(message, restore_key=None):
    return RemediationResult(REMEDIATOR_STATUS_SUCCESS, message, restore_key=restore_key)

class Remediator():
    def __init__(self, config_section_name):        
        self.name = config_section_name
        self.config = get_config()[config_section_name]

    @property
    def type(self): 
        return 'base'

    def remediate(self, target):
        if target.action == REMEDIATION_ACTION_REMOVE:
            return self.remove(target.key)
        return self.restore(target.key, target.restore_key)

    def remove(self, target):
        return RemediationFailure('remove not implemented')

    def restore(self, target, restore_target):
        return RemediationFailure('restore not implemented')

class RemediationTarget():
    def __init__(self, type=None, value=None, id=None):
        # set type and value
        self.type = type
        self.value = value

        # this is optional
        # if the remediation comes from an observable in an alert then this is the 
        # id from the observables table
        # this allows us to tie remediation to alerts via the observable_remediation_mapping table
        self.observable_database_id = None

        # if id is givent then decode it and use for type and value
        if id is not None:
            self.observable_database_id, self.type, self.value = b64decode(id.encode('ascii')).decode('utf-8').split('|', 2)

        # get remediation history for this target
        get_db().commit()
        query = get_db().query(Remediation)
        query = query.filter(Remediation.type == self.type)
        query = query.filter(Remediation.key == self.value)
        query = query.order_by(Remediation.id.desc())
        self.history = query.all()

    @property
    def id(self):
        # return an html/js friendly representation of the target
        return b64encode(f"{self.observable_database_id}|{self.type}|{self.value}".encode('utf-8')).decode('ascii')

    @property
    def processing(self):
        return len(self.history) > 0 and self.history[0].status != REMEDIATION_STATUS_COMPLETED

    @property
    def state(self):
        if len(self.history) > 0:
            if self.history[0].status == REMEDIATION_STATUS_COMPLETED:
                if self.history[0].successful:
                    return f'{self.history[0].action}d'
                return f'{self.history[0].action} failed'
            elif self.history[0].status == REMEDIATION_STATUS_IN_PROGRESS:
                return f'{self.history[0].action[:-1]}ing'
        return 'new'

    @property
    def css_class(self):
        if len(self.history) > 0:
            if self.history[0].status == REMEDIATION_STATUS_COMPLETED:
                if self.history[0].successful:
                    return 'success'
                return 'danger'
            elif self.history[0].status == REMEDIATION_STATUS_IN_PROGRESS:
                if self.history[0].successful:
                    return 'warning'
                return 'danger'
        return ''

    # return the last seen restore key or none if there are no restore keys
    @property
    def last_restore_key(self):
        if len(self.history) == 0:
            return None
        for h in self.history:
            if h.restore_key is not None:
                return h.restore_key
        return None

    # insert a remediation entry into the database which is then processed by the remediation service
    def queue(self, action, user_id):
        remediation = Remediation(
            action=action,
            type=self.type,
            key=self.value,
            successful=True,
            user_id=user_id,
            restore_key=self.last_restore_key,
        )
        get_db().add(remediation)
        get_db().flush()

        database_id = upsert_observable(create_observable(self.type, self.value))

        or_mapping = ObservableRemediationMapping(
            observable_id=database_id,
            remediation_id=remediation.id)
        get_db().add(or_mapping)

        get_db().commit()

    def stop_remediation(self):
        for h in self.history:
            if h.status != 'COMPLETED':
                h.status = 'COMPLETED'
                h.successful = False
        get_db().commit()

    def delete_remediation(self):
        for h in self.history:
            get_db().execute(Remediation.__table__.delete().where(Remediation.id == h.id))
        get_db().commit()

    def __lt__(self, other):
        return self.value < other.value

def get_remediation_targets(alert_uuids: list[str]) -> list[RemediationTarget]:
    """Returns a list of remediation targets for the given alert uuids."""
    targets: list[RemediationTarget] = []
    for alert_uuid in alert_uuids:
        alert = get_alert_by_uuid(alert_uuid)
        if alert is None:
            logging.warning(f"alert {alert_uuid} not found in remediation target list")
            continue

        alert.root_analysis.load()
        for observable in alert.root_analysis.all_observables:
            targets.extend(observable.remediation_targets)

    # 4/7/2021 - de-dupe this list, the type + value should be unique
    temp = {} # key = {x.type}{x.value}, value = target
    for target in targets:
        # map everything to the key, if it already exists just skip it
        key = f"{target.type}|{target.value}".lower()
        if key not in temp:
            temp[key] = target

    targets = list(temp.values())

    # return sorted list of targets
    return sorted(targets, key=lambda x: f"{x.observable_database_id}|{x.type}|{x.value}")

class RemediationService(ACEServiceInterface):
    def __init__(self):
        self.service_config = get_config()["service_remediation"]
        self.service_started = False
        self.service_stopping = False
        self.remediators = []
        self.uuid = str(uuid.uuid4())
        self.delay_time = timedelta(minutes=self.service_config.getint('delay_minutes', fallback=5))
        self.batch_size = self.service_config.getint('batch_size', fallback=1)
        self.max_threads = self.service_config.getint('max_threads', fallback=1)
        self.lock_timeout = timedelta(seconds=self.service_config.getint('lock_timeout_seconds', fallback=60))

    def start(self):
        self.service_started = True
        self.execute_service()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        return True
    
    def start_single_threaded(self):
        self.execute_service()

    def stop(self):
        self.service_stopping = True
    
    def wait(self):
        pass

    def execute_service(self):
        # load all remediators
        for section in get_config():
            if section.startswith('remediator_'):
                logging.info(f"Loading {section}")
                try:
                    module = importlib.import_module(get_config()[section]['module'])
                    remediator = getattr(module, get_config()[section]['class'])
                    self.remediators.append(remediator(section))
                except Exception as e:
                    logging.error(f"failed to load {section}: {e}")
                    report_exception()

        # process targets until shutdown event is set
        targets = []
        while not self.service_stopping:
            # if there are threads available
            if len(threading.enumerate()) - 1 < self.max_threads:
                # get targets to process if we have none
                if len(targets) == 0:
                    try:
                        targets = self.get_targets()
                    except Exception as e:
                        logging.error(f"call to get_targets() failed: {e}")
                        report_exception()
                    finally:
                        get_db().remove()

                # spawn thread to process worker
                if len(targets) > 0:
                    threading.Thread(target=self.remediate, args=(targets.pop(0),)).start()
            else:
                time.sleep(1)

        # wait for child threads to finish
        for thread in threading.enumerate():
            if thread.ident != threading.get_ident():
                logging.info(f"waiting for {thread}... (from {threading.current_thread()})")
                thread.join(5)

    def get_targets(self):
        # find targets to process
        logging.info('looking for new targets')
        query = get_db().query(Remediation)
        query = query.filter(or_(
            Remediation.lock == None,
            Remediation.lock_time < datetime.now(UTC) - self.lock_timeout,
        ))
        query = query.filter(Remediation.status != REMEDIATION_STATUS_COMPLETED)
        query = query.filter(or_(
            Remediation.update_time == None,
            Remediation.update_time < datetime.now(UTC) - self.delay_time,
        ))
        query = query.order_by(Remediation.insert_date.desc())
        query = query.limit(self.batch_size)
        target_ids = [t.id for t in query.all()]

        # wait a bit if there are no targets
        if len(target_ids) == 0:
            time.sleep(1)
            return []

        logging.info(f'found {len(target_ids)} targets')

        # attempt to lock found targets
        update = Remediation.__table__.update()
        update = update.values(
            lock = self.uuid,
            lock_time = datetime.now(UTC),
            status = REMEDIATION_STATUS_IN_PROGRESS,
        )
        update = update.where(Remediation.id.in_(target_ids))
        get_db().execute(update)
        get_db().commit()

        # fetch successfully locked targets
        query = get_db().query(Remediation)
        query = query.filter(Remediation.lock == self.uuid)
        query = query.order_by(Remediation.insert_date.desc())
        result = query.all()
        get_db().expunge_all()
        return result

    def remediate(self, target):
        try:
            logging.info(f"STARTED {target.action[:-1]}ing {target.type} {target.key}")

            # load results from previous runs
            results = {} if target.result is None else json.loads(target.result)

            # run all remediators on the target
            status = REMEDIATION_STATUS_COMPLETED
            restore_key = target.restore_key
            for remediator in self.remediators:
                # only run remediators for target type
                if remediator.type != target.type:
                    continue

                # only run remediators that are not already complete for this target
                if remediator.name not in results or results[remediator.name]['status'] not in COMPLETED_REMEDIATOR_STATUSES:
                    try:
                        # run the remediator on the target
                        results[remediator.name] = remediator.remediate(target)
                    except Exception as e:
                        # delay remediation and log error
                        results[remediator.name] = RemediationError(f"{e.__class__.__name__}: {e}")
                        # normally this would be an error but in our environment it is expected
                        logging.warning(f"{remediator.name} failed to {target.action} {target.type} {target.key}: {e}")
                        #logging.error(traceback.format_exc())

                    # delay remediation if not complete
                    if results[remediator.name]['status'] not in COMPLETED_REMEDIATOR_STATUSES:
                        status = REMEDIATION_STATUS_IN_PROGRESS

                    # set restore key if one was given
                    if results[remediator.name]['restore_key'] is not None:
                        restore_key = results[remediator.name]['restore_key']

            # mark as successful if no remediators failed/errored and at least one remediator succeeded
            successful = False
            for remediator in results:
                if results[remediator]['status'] in UNSUCCESSFUL_REMEDIATOR_STATUSES:
                    successful = False
                    break
                elif results[remediator]['status'] in SUCCESSFUL_REMEDIATOR_STATUSES:
                    successful = True

            # update target in remediation table
            update = Remediation.__table__.update()
            update = update.values(
                lock = None,
                status = status,
                successful = successful,
                result = json.dumps(results),
                restore_key = restore_key,
                update_time = datetime.now(UTC),
            )
            update = update.where(Remediation.id == target.id)
            get_db().execute(update)
            get_db().commit()

            # log result
            logging.info(f"{status} {target.action[:-1]}ing {target.type} {target.key}")

        except Exception as e:
            logging.error(f"Unhandled exception: {e}")
            report_exception()
        finally:
            try:
                get_db().remove()
            except Exception as e:
                logging.error(f"unable to return db session: {e}")
                report_exception()

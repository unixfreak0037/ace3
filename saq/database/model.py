import base64
import json
import logging
import os
import re
from typing import Optional
import uuid
import warnings

from flask_login import UserMixin
import pymysql
from sqlalchemy import BLOB, BOOLEAN, DATE, DATETIME, TIMESTAMP, VARBINARY, BigInteger, Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text, text
from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable as _Observable, get_observable_type_expiration_time
from saq.analysis.tag import Tag as _Tag
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_OPEN, EVENT_GLOBAL_OBSERVABLE_ADDED, EVENT_GLOBAL_TAG_ADDED, F_FILE, F_FQDN, F_URL, G_LOCK_TIMEOUT_SECONDS, QUEUE_DEFAULT
from saq.crypto import decrypt_chunk
from saq.database.meta import Base

from sqlalchemy.orm import reconstructor, relationship, validates, aliased
from sqlalchemy.orm.session import Session

from saq.database.pool import get_db, get_db_connection
from saq.database.retry import execute_with_retry, retry
from saq.database.util.sync import sync_observable
from saq.disposition import get_dispositions
from saq.environment import g_int, get_base_dir
from saq.error import report_exception
from saq.performance import track_execution_time
from saq.util import find_all_url_domains, validate_uuid

from werkzeug.security import generate_password_hash, check_password_hash

from saq.analysis.root import RootAnalysis


class Alert(Base):

    @classmethod
    def create_from_root_analysis(cls, root_analysis: RootAnalysis) -> "Alert":
        alert = cls(
            uuid=root_analysis.uuid,
            storage_dir=root_analysis.storage_dir,
            location=root_analysis.location,
            company_id=root_analysis.company_id,
            event_time=root_analysis.event_time,
            tool=root_analysis.tool,
            tool_instance=root_analysis.tool_instance,
            alert_type=root_analysis.alert_type,
            description=root_analysis.description,
            queue=root_analysis.queue,
        )
        #alert.root_analysis = root_analysis
        return alert

    def _initialize(self):
        # keep track of what Tag and Observable objects we add as we analyze
        self._tracked_tags = [] # of saq.analysis.Tag
        self._tracked_observables = [] # of saq.analysis.Observable
        self._synced_tags = set() # of Tag.name
        self._synced_observables = set() # of '{}:{}'.format(observable.type, observable.value)
        #self.add_event_listener(EVENT_GLOBAL_TAG_ADDED, self._handle_tag_added)
        #self.add_event_listener(EVENT_GLOBAL_OBSERVABLE_ADDED, self._handle_observable_added)

        # when we lock the Alert this is the UUID we used to lock it with
        self.lock_uuid = str(uuid.uuid4())

        self._observable_open_event_counts = None

        # this is the RootAnalysis object that this Alert is associated with
        self._root_analysis: Optional[RootAnalysis] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialize()

    @property
    def root_analysis(self) -> RootAnalysis:
        if self._root_analysis is None:
            self.load()

            if self._root_analysis is None:
                raise RuntimeError(f"failed to load root analysis for alert {self.uuid}")

        return self._root_analysis

    @reconstructor
    def init_on_load(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialize()

    def load(self):
        self._root_analysis = RootAnalysis(storage_dir=self.storage_dir)
        self._root_analysis.load()

        #try:
            #result = super().load(*args, **kwargs)
        #finally:
            ## the RootAnalysis object actually loads everything from JSON
            ## this may not exactly match what is in the database (it should)
            ## the data in the json is the authoritative source
            ## see https://ace-ecosystem.github.io/ACE/design/alert_storage/#alert-storage-vs-database-storage
            #session = Session.object_session(self)
            #if session:
                ## so if this alert is attached to a Session, at this point the session becomes dirty
                ## because we've loaded all the values from json that we've already loaded from the database
                ## so we discard those changes
                #session.expire(self)
                ## and then reload from the database
                #session.refresh(self)
                ## XXX inefficient but we'll move to a better design when we're fully containerized

        #return result

    __tablename__ = 'alerts'

    id = Column(
        Integer, 
        primary_key=True)

    company_id = Column(
        Integer,
        ForeignKey('company.id'),
        nullable=True)

    company = relationship('Company', foreign_keys=[company_id])

    uuid = Column(
        String(36), 
        unique=True, 
        nullable=False)

    location = Column(
        String(253),
        unique=False,
        nullable=False)

    storage_dir = Column(
        String(512), 
        unique=True, 
        nullable=False)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        server_default=text('CURRENT_TIMESTAMP'))

    event_time = Column(
        TIMESTAMP,
        nullable=True)

    tool = Column(
        String(256),
        nullable=False)

    tool_instance = Column(
        String(1024),
        nullable=False)

    alert_type = Column(
        String(64),
        nullable=False)

    description = Column(
        String(1024),
        nullable=False)

    priority = Column(
        Integer,
        nullable=False,
        default=0)

    disposition = Column(
        String(64),
        nullable=False,
        default=DISPOSITION_OPEN)

    queue = Column(
        String(64),
        nullable=False,
        default=QUEUE_DEFAULT)

    disposition_user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True)

    disposition_time = Column(
        TIMESTAMP, 
        nullable=True)

    owner_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True)

    owner_time = Column(
        TIMESTAMP,
        nullable=True)

    archived = Column(
        BOOLEAN, 
        nullable=False,
        default=False)

    removal_user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True)

    removal_time = Column(
        TIMESTAMP,
        nullable=True)

    # relationships
    disposition_user = relationship('User', foreign_keys=[disposition_user_id])
    owner = relationship('User', foreign_keys=[owner_id])
    remover = relationship('User', foreign_keys=[removal_user_id])
    #observable_mapping = relationship('ObservableMapping')
    tag_mappings = relationship('TagMapping', passive_deletes=True, passive_updates=True, lazy='joined', overlaps="tag_mapping")
    #delayed_analysis = relationship('DelayedAnalysis')

    def get_observables(self):
        query = get_db().query(Observable)
        query = query.join(ObservableMapping, Observable.id == ObservableMapping.observable_id)
        query = query.join(Alert, ObservableMapping.alert_id == Alert.id)
        query = query.filter(Alert.uuid == self.uuid)
        query = query.group_by(Observable.id)
        return query.all()

    # XXX revist this weird thing -- no idea why this is designed like this
    def get_remediation_targets(self):
        # XXX hack to get around circular import - probably need to merge some modules into one
        from saq.observables import create_observable
        return []

        # get observables for this alert
        observables = self.get_observables()

        # get remediation targets for each observable
        targets = {}
        for o in observables:
            observable = create_observable(o.type, o.display_value)
            # create observable returns none if the value is bad for the type (e.g. 123 is not a valid ipv4)
            if observable is None:
                continue
            observable.alert = self
            for target in observable.remediation_targets:
                targets[target.id] = target

        # return sorted list of targets
        targets = list(targets.values())
        targets.sort(key=lambda x: f"{x.type}|{x.value}")
        return targets

    def get_remediation_status(self):
        targets = self.get_remediation_targets()
        remediations = []
        for target in targets:
            if len(target.history) > 0:
                remediations.append(target.history[0])

        if len(remediations) == 0:
            return 'new'

        s = 'success'
        for r in remediations:
            if not r.successful:
                return 'failed'
            if r.status != 'COMPLETED':
                s = 'processing'
        return s

    @property
    def wiki(self) -> str:
        return ''

    @property
    def observable_open_event_counts(self):
        """
        Returns a dictionary containing the open events as the keys and the number of observables in this alert
        that are also in alerts in the event.

        {<event>: # of observables in this alert that are also in the event}
        """
        return {}

        if self._observable_open_event_counts is None:
            results = dict()

            # Skip file observables. The calculations will consider their hash observables instead.
            for observable in [o for o in self.root_analysis.observable_store.values() if o.type != F_FILE]:
                if 'OPEN' in observable.matching_events_by_status:
                    for event in observable.matching_events_by_status['OPEN']:
                        if event not in results:
                            results[event] = 0

                        results[event] += 1

            self._observable_open_event_counts = results

        return self._observable_open_event_counts

    @property
    def remediation_status(self):
        if not self.observable_mappings:
            return ''

        remediations = []
        for om in self.observable_mappings:
            for orm in om.observable.observable_remediation_mappings:
                remediations.append(orm.remediation)

        if len(remediations) == 0:
            return 'new'

        s = 'success'
        for rem in remediations:
            if not rem.successful:
                return 'failed'
            if rem.status != 'COMPLETED':
                s = 'processing'
        return s

        #return self._remediation_status if hasattr(self, '_remediation_status') else self.get_remediation_status()

    @property
    def remediation_targets(self):
        return self._remediation_targets if hasattr(self, '_remediation_targets') else self.get_remediation_targets()

    @property
    def all_email_analysis(self) -> list[Analysis]:
        from saq.modules.email import EmailAnalysis
        observables = self.root_analysis.find_observables(lambda o: o.get_analysis(EmailAnalysis))
        return [o.get_analysis(EmailAnalysis) for o in observables]

    @property
    def has_email_analysis(self) -> bool:
        from saq.modules.email import EmailAnalysis
        return bool(self.root_analysis.find_observable(lambda o: o.get_analysis(EmailAnalysis)))

    @property
    def has_renderer_screenshot(self) -> bool:
        # XXX needs to be updated
        return False

    @property
    def screenshots(self) -> list[dict]:
        return [
            {'alert_id': self.uuid, 'observable_id': o.id, 'scaled_width': o.scaled_width, 'scaled_height': o.scaled_height}
            for o in self.all_observables
            if (
                    o.type == F_FILE
                    and o.is_image
                    and o.file_name.startswith('renderer_')
                    and o.file_name.endswith('.png')
            )
        ]


    @property
    def icon(self):
        # use alert type as icon name if it exists
        icon_files = os.listdir(os.path.join(get_base_dir(), 'app', 'static', 'images', 'alert_icons'))
        if f'{self.alert_type}.png' in icon_files:
            return self.alert_type

        # otherwise do this old thing that is wildly over complicated
        description_tokens = {token.lower() for token in re.split('[ _]', self.description)}
        tool_tokens = {token.lower() for token in self.tool.split(' ')}
        type_tokens = {token.lower() for token in self.alert_type.split(' ')}

        available_favicons = set([k for k in get_config()['gui_favicons']])

        result = available_favicons.intersection(description_tokens)
        if not result:
            result = available_favicons.intersection(tool_tokens)
            if not result:
                result = available_favicons.intersection(type_tokens)

        if not result:
            return 'default'
        else:
            return result.pop()


    @validates('description')
    def validate_description(self, key, value):
        max_length = getattr(self.__class__, key).prop.columns[0].type.length
        if value and len(value) > max_length:
            return value[:max_length]
        return value


    def archive(self, *args, **kwargs):
        if self.archived is True:
            logging.warning(f"called archive() on {self} but already archived")
            return None

        result = self.root_analysis.archive(*args, **kwargs)
        self.archived = True
        return result


    #lock_owner = Column(
        #String(256), 
        #nullable=True)

    #lock_id = Column(
        #String(36),
        #nullable=True)

    #lock_transaction_id = Column(
        #String(36),
        #nullable=True)

    #lock_time = Column(
        #TIMESTAMP, 
        #nullable=True)

    detection_count = Column(
        Integer,
        default=0)

    @property
    def status(self):
        if self.lock is not None:
            return 'Analyzing ({})'.format(self.lock.lock_owner)

        if self.delayed_analysis is not None:
            return 'Delayed ({})'.format(self.delayed_analysis.analysis_module)
    
        if self.workload is not None:
            return 'New'

        # XXX this kind of sucks -- find a different way to do this
        if self.removal_time is not None:
            return 'Completed (Removed)'

        return 'Completed'


    @property
    def sorted_tags(self):
        tags = {}
        for tag_mapping in self.tag_mappings:
            tags[tag_mapping.tag.name] = tag_mapping.tag
        return sorted([x for x in tags.values()], key=lambda x: (-x.score, x.name.lower()))

    # we also save these database properties to the JSON data

    KEY_DATABASE_ID = 'database_id'
    KEY_PRIORITY = 'priority'
    KEY_DISPOSITION = 'disposition'
    KEY_DISPOSITION_USER_ID = 'disposition_user_id'
    KEY_DISPOSITION_TIME = 'disposition_time'
    KEY_OWNER_ID = 'owner_id'
    KEY_OWNER_TIME = 'owner_time'
    KEY_REMOVAL_USER_ID = 'removal_user_id'
    KEY_REMOVAL_TIME = 'removal_time'

    @property
    def json(self):
        result = RootAnalysis.json.fget(self)
        result.update({
            Alert.KEY_DATABASE_ID: self.id,
            Alert.KEY_PRIORITY: self.priority,
            Alert.KEY_DISPOSITION: self.disposition,
            Alert.KEY_DISPOSITION_USER_ID: self.disposition_user_id,
            Alert.KEY_DISPOSITION_TIME: self.disposition_time,
            Alert.KEY_OWNER_ID: self.owner_id,
            Alert.KEY_OWNER_TIME: self.owner_time,
            Alert.KEY_REMOVAL_USER_ID: self.removal_user_id,
            Alert.KEY_REMOVAL_TIME: self.removal_time
        })
        return result

    @json.setter
    def json(self, value):
        assert isinstance(value, dict)
        RootAnalysis.json.fset(self, value)

        if not self.id:
            if Alert.KEY_DATABASE_ID in value:
                self.id = value[Alert.KEY_DATABASE_ID]

        if not self.disposition:
            if Alert.KEY_DISPOSITION in value:
                self.disposition = value[Alert.KEY_DISPOSITION]

        if not self.disposition_user_id:
            if Alert.KEY_DISPOSITION_USER_ID in value:
                self.disposition_user_id = value[Alert.KEY_DISPOSITION_USER_ID]

        if not self.disposition_time:
            if Alert.KEY_DISPOSITION_TIME in value:
                self.disposition_time = value[Alert.KEY_DISPOSITION_TIME]

        if not self.owner_id:
            if Alert.KEY_OWNER_ID in value:
                self.owner_id = value[Alert.KEY_OWNER_ID]

        if not self.owner_time:
            if Alert.KEY_OWNER_TIME in value:
                self.owner_time = value[Alert.KEY_OWNER_TIME]

        if not self.removal_user_id:
            if Alert.KEY_REMOVAL_USER_ID in value:
                self.removal_user_id = value[Alert.KEY_REMOVAL_USER_ID]

        if not self.removal_time:
            if Alert.KEY_REMOVAL_TIME in value:
                self.removal_time = value[Alert.KEY_REMOVAL_TIME]

    #def track_delayed_analysis_start(self, observable, analysis_module):
        #super().track_delayed_analysis_start(observable, analysis_module)
        ##with get_db_connection() as db:
            #c = db.cursor()
            #c.execute("""INSERT INTO delayed_analysis ( alert_id, observable_id, analysis_module ) VALUES ( %s, %s, %s )""",
                     #(self.id, observable.id, analysis_module.config_section_name))
            #db.commit()

    #def track_delayed_analysis_stop(self, observable, analysis_module):
        #super().track_delayed_analysis_stop(observable, analysis_module)
        #with get_db_connection() as db:
            #c = db.cursor()
            #c.execute("""DELETE FROM delayed_analysis where alert_id = %s AND observable_id = %s AND analysis_module = %s""",
                     #(self.id, observable.id, analysis_module.config_section_name))
            #db.commit()

    def _handle_tag_added(self, source, event_type, *args, **kwargs):
        assert args
        assert isinstance(args[0], _Tag)
        tag = args[0]

        try:
            self.sync_tag_mapping(tag)
        except Exception as e:
            logging.error("sync_tag_mapping failed: {}".format(e))
            report_exception()

    def sync_tag_mapping(self, tag):
        tag_id = None

        with get_db_connection() as db:
            cursor = db.cursor()
            for _ in range(3): # make sure we don't enter an infinite loop here
                cursor.execute("SELECT id FROM tags WHERE name = %s", ( tag.name, ))
                result = cursor.fetchone()
                if result:
                    tag_id = result[0]
                    break
                else:
                    try:
                        execute_with_retry(db, cursor, "INSERT IGNORE INTO tags ( name ) VALUES ( %s )""", ( tag.name, ))
                        db.commit()
                        continue
                    except pymysql.err.InternalError as e:
                        if e.args[0] == 1062:

                            # another process added it just before we did
                            try:
                                db.rollback()
                            except:
                                pass

                            break
                        else:
                            raise e

            if not tag_id:
                logging.error("unable to find tag_id for tag {}".format(tag.name))
                return

            try:
                execute_with_retry(db, cursor, "INSERT IGNORE INTO tag_mapping ( alert_id, tag_id ) VALUES ( %s, %s )", ( self.id, tag_id ))
                db.commit()
                logging.debug("mapped tag {} to {}".format(tag, self))
            except pymysql.err.InternalError as e:
                if e.args[0] == 1062: # already mapped
                    return
                else:
                    raise e

    def _handle_observable_added(self, source, event_type, *args, **kwargs):
        assert args
        assert isinstance(args[0], _Observable)
        observable = args[0]

        try:
            self.sync_observable_mapping(observable)
        except Exception as e:
            logging.error("sync_observable_mapping failed: {}".format(e))
            #report_exception()

    @retry
    def sync_observable_mapping(self, observable):
        assert isinstance(observable, _Observable)

        existing_observable = sync_observable(observable)
        assert existing_observable.id is not None
        get_db().execute(ObservableMapping.__table__.insert().prefix_with('IGNORE').values(observable_id=existing_observable.id, alert_id=self.id))
        get_db().commit()

    @retry
    def sync(self, build_index=True):
        """Saves the Alert to disk and database."""
        assert self.storage_dir is not None # requires a valid storage_dir at this point
        assert isinstance(self.storage_dir, str)

        if self.root_analysis:
            self.root_analysis.save()

        # XXX is this check still required?
        # newly generated alerts will have a company_name but no company_id
        # we look that up here if we don't have it yet if self.company_name and not self.company_id:
        #if self.company_name and not self.company_id:
            #self.company_id = get_db().query(Company).filter(Company.name == self.company_name).one().id
            #with get_db_connection() as db:
                #c = db.cursor()
                #c.execute("SELECT `id` FROM company WHERE `name` = %s", (self.company_name))
                #row = c.fetchone()
                #if row:
                    #logging.debug("found company_id {} for company_name {}".format(self.company_id, self.company_name))
                    #self.company_id = row[0]

        # compute number of detection points
        self.detection_count = len(self.root_analysis.all_detection_points)

        # save the alert to the database
        session = Session.object_session(self)
        if session is None:
            session = get_db()()
        
        session.add(self)
        session.commit()
        if build_index:
            self.build_index()

        #self.root_analysis.save() # save this alert now that it has the id

        # we want to unlock it here since the corelation is going to want to pick it up as soon as it gets added
        #if self.is_locked():
            #self.unlock()

        return True

    #def lock(self):
        #"""Acquire a lock on the analysis. Returns True if a lock was obtained, False otherwise."""
        #return acquire_lock(self.uuid, self.lock_uuid, lock_owner="Alert ({})".format(os.getpid()))

    #def unlock(self):
        #"""Releases a lock on the analysis."""
        #return release_lock(self.uuid, self.lock_uuid)

    def is_locked(self):
        """Returns True if this Alert has already been locked."""
        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""SELECT uuid FROM locks WHERE uuid = %s AND TIMESTAMPDIFF(SECOND, lock_time, NOW()) < %s""", 
                     (self.uuid, g_int(G_LOCK_TIMEOUT_SECONDS)))
            return c.fetchone() is not None

    #@track_execution_time
    #def sync_tracked_objects(self):
        #"""Updates the observable_mapping and tag_mapping tables according to what objects were added during analysis."""
        # make sure we have something to do
        #if not self._tracked_tags and not self._tracked_observables:
            #return

        #with get_db_connection() as db:
            #c = db.cursor()
            #if self._tracked_tags:
                #logging.debug("syncing {} tags to {}".format(len(self._tracked_tags), self))
                #self._sync_tags(db, c, self._tracked_tags)

            #if self._tracked_observables:
                #logging.debug("syncing {} observables to {}".format(len(self._tracked_observables), self))
                #self._sync_observables(db, c, self._tracked_observables)

            #db.commit()

        #self._tracked_tags.clear()
        #self._tracked_observables.clear()

    #def flush(self):
        #super().flush()
        
        # if this Alert is in the database then
        # we want to go ahead and update if we added any new Tags or Observables
        #if self.id:
            #self.sync_tracked_objects()

    def reset(self):
        super().reset()

        if self.id:
            # rebuild the index after we reset the Alert
            self.rebuild_index()

    def build_index(self):
        """Rebuilds the data for this Alert in the observables, tags, observable_mapping and tag_mapping tables."""
        self.rebuild_index()

    def rebuild_index(self):
        """Rebuilds the data for this Alert in the observables, tags, observable_mapping and tag_mapping tables."""
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with get_db_connection() as db:
                c = db.cursor()
                execute_with_retry(db, c, self._rebuild_index)

    def _rebuild_index(self, db, c):
        logging.info(f"rebuilding indexes for {self}")
        c.execute("""DELETE FROM observable_mapping WHERE alert_id = %s""", ( self.id, ))
        c.execute("""DELETE FROM tag_mapping WHERE alert_id = %s""", ( self.id, ))
        c.execute("""DELETE FROM observable_tag_index WHERE alert_id = %s""", ( self.id, ))

        tag_names = tuple([ tag.name for tag in self.root_analysis.all_tags ])
        if tag_names:
            sql = "INSERT IGNORE INTO tags ( name ) VALUES {}".format(','.join(['(%s)' for name in tag_names]))
            c.execute(sql, tag_names)

        all_observables = self.root_analysis.all_observables

        observables = []
        for observable in all_observables:
            observables.append(observable.type)
            observables.append(observable.value)
            observables.append(observable.sha256_hash)

            expires_on = get_observable_type_expiration_time(observable.type)
            if expires_on:
                observables.append(expires_on.strftime('%Y-%m-%d %H:%M:%S'))
            else:
                observables.append(None)

        observables = tuple(observables)

        if all_observables:
            sql = "INSERT IGNORE INTO observables ( type, value, sha256, expires_on ) VALUES {}".format(','.join('(%s, %s, UNHEX(%s), %s)' for o in all_observables))
            c.execute(sql, observables)

        tag_mapping = {} # key = tag_name, value = tag_id
        if tag_names:
            sql = "SELECT id, name FROM tags WHERE name IN ( {} )".format(','.join(['%s' for name in tag_names]))
            c.execute(sql, tag_names)

            for row in c:
                tag_id, tag_name = row
                tag_mapping[tag_name] = tag_id

            sql = "INSERT INTO tag_mapping ( alert_id, tag_id ) VALUES {}".format(','.join(['(%s, %s)' for name in tag_mapping.values()]))
            parameters = []
            for tag_id in tag_mapping.values():
                parameters.append(self.id)
                parameters.append(tag_id)

            c.execute(sql, tuple(parameters))

        observable_mapping = {} # key = observable_type+observable_sha256, value = observable_id
        if all_observables:
            and_pairs = []
            params = []
            for o in all_observables:
                params.append(o.type)
                params.append(o.sha256_hash)
                and_pairs.append('(type=%s AND sha256=UNHEX(%s))')

            or_string = ' OR '.join(and_pairs)

            sql = f'SELECT id, type, HEX(sha256) FROM observables WHERE {or_string}'
            c.execute(sql, tuple(params))

            for row in c:
                observable_id, observable_type, sha256_hex = row
                observable_mapping[f'{observable_type}{sha256_hex.lower()}'] = observable_id

            sql = "INSERT INTO observable_mapping ( alert_id, observable_id ) VALUES {}".format(','.join(['(%s, %s)' for o in observable_mapping.keys()]))
            parameters = []
            for observable_id in observable_mapping.values():
                parameters.append(self.id)
                parameters.append(observable_id)

            c.execute(sql, tuple(parameters))

        sql = "INSERT IGNORE INTO observable_tag_index ( alert_id, observable_id, tag_id ) VALUES "
        parameters = []
        sql_clause = []

        for observable in all_observables:
            for tag in observable.tags:
                try:
                    tag_id = tag_mapping[tag.name]
                except KeyError:
                    logging.debug(f"missing tag mapping for tag {tag.name} in observable {observable} alert {self.uuid}")
                    continue

                observable_id = observable_mapping[f'{observable.type}{observable.sha256_hash.lower()}']

                parameters.append(self.id)
                parameters.append(observable_id)
                parameters.append(tag_id)
                sql_clause.append('(%s, %s, %s)')

        if sql_clause:
            sql += ','.join(sql_clause)
            c.execute(sql, tuple(parameters))

        db.commit()
        
    @track_execution_time
    def rebuild_index_old(self):
        """Rebuilds the data for this Alert in the observables, tags, observable_mapping and tag_mapping tables."""
        logging.debug("updating detailed information for {}".format(self))

        with get_db_connection() as db:
            c = db.cursor()
            c.execute("""DELETE FROM observable_mapping WHERE alert_id = %s""", ( self.id, ))
            c.execute("""DELETE FROM tag_mapping WHERE alert_id = %s""", ( self.id, ))
            db.commit()

        self.build_index()

    def similar_alerts(self):
        """Returns list of similar alerts uuid, similarity score and disposition."""
        similarities = []

        #with get_db_connection() as db:
            #c = db.cursor()
            #c.execute("""SELECT count(*) FROM tag_mapping where alert_id = %s group by alert_id""", (self.id))
            #result = c.fetchone()
            #db.commit()
            #if result is None:
                #return similarities

            #num_tags = result[0]
            #if num_tags == 0:
                #return similarities

            #c.execute("""
                #SELECT alerts.uuid, alerts.disposition, 200 * count(*)/(total + %s) AS sim
                #FROM tag_mapping tm1
                #JOIN tag_mapping tm2 ON tm1.tag_id = tm2.tag_id
                #JOIN (SELECT alert_id, count(*) AS total FROM tag_mapping GROUP BY alert_id) AS t1 ON tm1.alert_id = t1.alert_id
                #JOIN alerts on tm1.alert_id = alerts.id
                #WHERE tm2.alert_id = %s AND tm1.alert_id != %s AND alerts.disposition IS NOT NULL AND (alerts.alert_type != 'faqueue' OR (alerts.disposition != 'FALSE_POSITIVE' AND alerts.disposition != 'IGNORE'))
                #GROUP BY tm1.alert_id
                #ORDER BY sim DESC, alerts.disposition_time DESC
                #LIMIT 10
                #""", (num_tags, self.id, self.id))
            #results = c.fetchall()
            #if results is None:
                #return similarities

            #for result in results:
                #similarities.append(Similarity(result[0], result[1], result[2]))

        return similarities

    #@property
    #def delayed(self):
        #try:
            #return len(self.delayed_analysis) > 0
        #except DetachedInstanceError:
            #with get_db_connection() as db:
                #c = db.cursor()
                #c.execute("SELECT COUNT(*) FROM delayed_analysis WHERE alert_id = %s", (self.id,))
                #result = c.fetchone()
                #if not result:
                    #return

                #return result[0]

    #@delayed.setter
    #def delayed(self, value):
        #pass

    ### HERE


    @property
    def node_location(self):
        return self.nodes.location

def load_alert(uuid: str) -> Optional[Alert]:
    """Returns the loaded Alert given by uuid, or None if the alert does not exist."""
    alert = get_db().query(Alert).filter(Alert.uuid == uuid).one_or_none()

    if alert:
        alert.load()

    return alert

class Campaign(Base):
    __tablename__ = 'campaign'
    id = Column(Integer, nullable=False, primary_key=True)
    name = Column(String(128), nullable=False)

class Company(Base):

    __tablename__ = 'company'

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, index=True)

    @property
    def json(self):
        return {
            'id': self.id,
            'name': self.name }

class Config(Base):

    __tablename__ = 'config'

    key = Column(String(512), primary_key=True)
    value = Column(Text, nullable=False)

class DelayedAnalysis(Base):

    __tablename__ = 'delayed_analysis'

    id = Column(
        Integer,
        primary_key=True)

    uuid = Column(
        String(36),
        nullable=False,
        index=True)

    observable_uuid = Column(
        String(36),
        nullable=False)

    analysis_module = Column(
        String(512),
        nullable=False)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    delayed_until = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    node_id = Column(
        Integer,
        nullable=False, 
        index=True)

    storage_dir = Column(
        String(1024), 
        unique=False, 
        nullable=False)


class EventStatus(Base):
    __tablename__ = 'event_status'

    id = Column(Integer, nullable=False, primary_key=True)
    value = Column(String(50), nullable=False, unique=True)

class EventRemediation(Base):
    __tablename__ = 'event_remediation'

    id = Column(Integer, nullable=False, primary_key=True)
    value = Column(String(50), nullable=False, unique=True)

class EventVector(Base):
    __tablename__ = 'event_vector'

    id = Column(Integer, nullable=False, primary_key=True)
    value = Column(String(50), nullable=False, unique=True)

class EventRiskLevel(Base):
    __tablename__ = 'event_risk_level'

    id = Column(Integer, nullable=False, primary_key=True)
    value = Column(String(50), nullable=False, unique=True)

class EventPreventionTool(Base):
    __tablename__ = 'event_prevention_tool'

    id = Column(Integer, nullable=False, primary_key=True)
    value = Column(String(50), nullable=False, unique=True)

class EventType(Base):
    __tablename__ = 'event_type'

    id = Column(Integer, nullable=False, primary_key=True)
    value = Column(String(50), nullable=False, unique=True)

class Event(Base):
    __tablename__ = 'events'

    id = Column(Integer, nullable=False, primary_key=True)
    uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    creation_date = Column(DATE, nullable=False)
    name = Column(String(128), nullable=False)
    status = relationship('EventStatus')
    status_id = Column(Integer, ForeignKey('event_status.id'), nullable=False)
    remediation = relationship('EventRemediation')
    remediation_id = Column(Integer, ForeignKey('event_remediation.id'), nullable=False)
    comment = Column(Text)
    vector = relationship('EventVector', lazy='joined')
    vector_id = Column(Integer, ForeignKey('event_vector.id'), nullable=False)
    risk_level = relationship('EventRiskLevel')
    risk_level_id = Column(Integer, ForeignKey('event_risk_level.id'), nullable=False)
    prevention_tool = relationship('EventPreventionTool')
    prevention_tool_id = Column(Integer, ForeignKey('event_prevention_tool.id'), nullable=False)
    campaign_id = Column(Integer, ForeignKey('campaign.id'), nullable=True)
    campaign = relationship('Campaign', foreign_keys=[campaign_id])
    type = relationship('EventType', lazy='joined')
    type_id = Column(Integer, ForeignKey('event_type.id'), nullable=False)
    malware = relationship('MalwareMapping', passive_deletes=True, passive_updates=True)
    #alert_mappings = relationship('EventMapping', passive_deletes=True, passive_updates=True)
    companies = relationship('CompanyMapping', passive_deletes=True, passive_updates=True)
    event_time = Column(DATETIME, nullable=True)
    alert_time = Column(DATETIME, nullable=True)
    ownership_time = Column(DATETIME, nullable=True)
    disposition_time = Column(DATETIME, nullable=True)
    contain_time = Column(DATETIME, nullable=True)
    remediation_time = Column(DATETIME, nullable=True)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    owner = relationship('User', foreign_keys=[owner_id])

    @property
    def json(self):
        return {
            'id': self.id,
            'uuid': self.uuid,
            'alerts': self.alerts,
            'campaign': self.campaign.name if self.campaign else None,
            'comment': self.comment,
            'companies': self.company_names,
            'creation_date': str(self.creation_date),
            'event_time': str(self.event_time),
            'alert_time': str(self.alert_time),
            'ownership_time': str(self.ownership_time),
            'disposition_time': str(self.ownership_time),
            'contain_time': str(self.contain_time),
            'remediation_time': str(self.remediation_time),
            'disposition': self.disposition,
            'malware': [{mal.name: [t.type for t in mal.threats]} for mal in self.malware],
            'name': self.name,
            'prevention_tool': self.prevention_tool.value,
            'remediation': self.remediation.value,
            'risk_level': self.risk_level.value,
            'status': self.status.value,
            'tags': self.sorted_tags,
            'type': self.type.value,
            'vector': self.vector.value,
            'wiki': self.wiki,
            'owner': self.owner
        }

    @property
    def alerts(self):
        uuids = []
        for alert in self.alert_mappings:
            uuids.append(alert.uuid)
        return uuids

    @property
    def alert_objects(self) -> list["Alert"]:
        return [m.alert for m in self.alert_mappings]

    # XXX get rid of this
    @property
    def all_observables_sorted(self) -> list[_Observable]: # XXX
        """Returns a sorted list (by type, then value) of all of the unique observables in all of the alerts in the
        event. It prefers to add observables that have FA Queue results. So if the same observable is in multiple
        alerts, but only one has FA Queue results, it will add that one to the list."""

        observables = []

        for alert in self.alert_objects:
            for observable in alert.root_analysis.all_observables:

                # Check if this observable is already in the list
                existing_observable = next((o for o in observables if o == observable), None)

                # If it is, then make sure the one that is in the list has FA Queue analysis
                if existing_observable:

                    # Continue if the version of the observable already in the list has FA Queue analysis
                    if existing_observable.faqueue_hits is not None:
                        continue

                    # If this current observable has FA Queue analysis, remove the existing observable and add the
                    # current one to the list instead
                    if observable.faqueue_hits is not None:
                        observables.remove(existing_observable)
                        observables.append(observable)

                # We haven't seen this observable yet, so just add it to the list
                else:
                    observables.append(observable)

        return sorted(observables, key=lambda o: (o.type, o.value))

    @property
    def alerts_still_analyzing(self) -> bool:
        """Returns True if any of the alerts in the event have not completed their analysis."""
        return any('Completed' not in a.status for a in self.alert_objects)

    @property
    def malware_names(self):
        names = []
        for mal in self.malware:
            names.append(mal.name)
        return names

    @property
    def company_names(self):
        names = []
        for company in self.companies:
            names.append(company.name)
        return names

    @property
    def commentf(self):
        if self.comment is None:
            return ""
        return self.comment

    @property
    def threats(self):
        threats = {}
        for mal in self.malware:
            for threat in mal.threats:
                threats[threat.type] = True
        return threats.keys()

    @property
    def disposition(self):
        if not self.alert_mappings:
            disposition = DISPOSITION_DELIVERY
        else:
            disposition = DISPOSITION_OPEN

        for alert_mapping in self.alert_mappings:
            if alert_mapping.alert.disposition == DISPOSITION_OPEN:
                logging.warning(f"alert {alert_mapping.alert} added to event without disposition {alert_mapping.event_id}")
                continue

            try:
                if get_dispositions()[alert_mapping.alert.disposition]['rank'] > get_dispositions()[disposition]['rank']:
                    disposition = alert_mapping.alert.disposition
            except:
                pass

        return disposition

    @property
    def disposition_rank(self):
        return get_dispositions()[self.disposition]['rank']

    @property
    def sorted_tags(self) -> list[str]:
        results = get_db().query(Tag.name) \
            .join(TagMapping, Tag.id == TagMapping.tag_id) \
            .join(Alert, TagMapping.alert_id == Alert.id) \
            .join(EventMapping, Alert.id == EventMapping.alert_id) \
            .filter(EventMapping.event_id == self.id).distinct().all()

        return sorted([result[0] for result in results])

    @property
    def wiki(self) -> str:
        return ''

    @property
    def alert_with_email_and_screenshot(self) -> "Alert":
        return next((a for a in self.alert_objects if a.has_email_analysis and a.has_renderer_screenshot), None)

    @property
    def all_sandbox_reports(self) -> list[dict]:
        from saq.modules.sandbox import merge_sandbox_reports

        # Build a dict of the sandbox reports with the sample's MD5 as the key:
        # {'sample_md5': [{sandbox1_report}, {sandbox2_report}...]}
        sandbox_reports = {}

        for alert in self.alert_objects:
            alert_sandbox_analyses = set()

            for analysis in alert_sandbox_analyses:
                if hasattr(analysis, 'report') and analysis.report:
                    if isinstance(analysis.report, dict):
                        if analysis.report['md5']:
                            if analysis.report['md5'] not in sandbox_reports:
                                sandbox_reports[analysis.report['md5']] = []

                            if analysis.report not in sandbox_reports[analysis.report['md5']]:
                                sandbox_reports[analysis.report['md5']].append(analysis.report)
                    else:
                        logging.warning(f'{type(analysis)} analysis.report: {analysis.report}')

        # Now merge all of the sandbox reports in each MD5's list:
        # [{merged_sandbox_report}, {merged2_sandbox_report}...]
        merged_sandbox_reports = []
        for sample_md5 in sandbox_reports:
            merged_sandbox_reports.append(merge_sandbox_reports(sandbox_reports[sample_md5]))

        return merged_sandbox_reports

    @property
    def all_file_observables(self) -> list[_Observable]:
        file_observables = []

        for alert in self.alert_objects:
            for observable in alert.root_analysis.find_observables(lambda o: o.type == F_FILE):
                file_observables.append(observable)

        return file_observables

    @property
    def all_sandbox_dropped_files(self):
        from saq.modules.sandbox import DroppedFileList

        all_dropped_files = DroppedFileList()
        for sandbox_report in self.all_sandbox_reports:
            for dropped_file in sandbox_report['dropped_files']:
                all_dropped_files.append(dropped_file)

        return all_dropped_files

    @property
    def all_sandbox_samples(self) -> list[_Observable]:
        all_sandbox_samples = []
        for file_observable in self.all_file_observables:
            if any('sandbox_sample' in tag.name.lower() for tag in file_observable.tags):
                all_sandbox_samples.append(file_observable)

        return all_sandbox_samples

    @property
    def all_email_file_observables(self) -> list[_Observable]:
        from saq.modules.email import EmailAnalysis

        file_observables = []

        for alert in self.alert_objects:
            for observable in alert.root_analysis.find_observables(lambda o: o.type == F_FILE):
                if observable.get_analysis(EmailAnalysis):
                    file_observables.append(observable)

        return file_observables

    @property
    def all_emails(self) -> set[Analysis]:
        from saq.modules.email import EmailAnalysis

        emails = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.get_analysis(EmailAnalysis))
            email_analyses = {o.get_analysis(EmailAnalysis) for o in observables}

            # Inject the alert's UUID into the EmailAnalysis so that we maintain a link of alert->email
            for email_analysis in email_analyses:
                email_analysis.alert_uuid = alert.uuid

            emails |= email_analyses

        return emails

    @property
    def all_url_domain_counts(self) -> dict[str, int]:
        url_domain_counts = {}

        for alert in self.alert_objects:
            domain_counts = find_all_url_domains(alert.root_analysis)
            for d in domain_counts:
                if d not in url_domain_counts:
                    url_domain_counts[d] = domain_counts[d]
                else:
                    url_domain_counts[d] += domain_counts[d]

        return url_domain_counts

    @property
    def all_urls(self) -> set[str]:
        urls = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.type == F_URL)
            urls |= {o.value for o in observables}

        return urls

    @property
    def all_fqdns(self) -> set[str]:
        fqdns = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.type == F_FQDN)
            fqdns |= {o.value for o in observables}

        return fqdns

    @property
    def all_user_analysis(self) -> set[Analysis]:
        from saq.modules.user import UserAnalysis
        user_analysis = set()

        for alert in self.alert_objects:
            observables = alert.root_analysis.find_observables(lambda o: o.get_analysis(UserAnalysis))
            user_analysis |= {o.get_analysis(UserAnalysis) for o in observables}

        return user_analysis

    @property
    def showable_tags(self) -> dict[str, list]:
        special_tag_names = [tag for tag in get_config()['tags'] if get_config()['tags'][tag] in ['special', 'hidden']]

        results = {}
        for alert in self.alert_objects:
            results[alert.uuid] = []
            for tag in alert.sorted_tags:
                if tag.name not in special_tag_names:
                    results[alert.uuid].append(tag)

        return results

    @property
    def tags(self) -> list:
        """Returns a list of Tag objects that are currently mapped to this event"""
        ignore_tags = [tag for tag in get_config()['tags'].keys() if get_config()['tags'][tag] in ['special', 'hidden']]
        tags = get_db().query(Tag). \
            join(EventTagMapping, Tag.id == EventTagMapping.tag_id). \
            join(Event, Event.id == EventTagMapping.event_id). \
            filter(Event.id == self.id, Tag.name.notin_(ignore_tags)). \
            order_by(Tag.name.asc()).all()

        return tags





class Lock(Base):
    
    __tablename__ = 'locks'

    uuid = Column(
        String(36),
        primary_key=True)

    lock_uuid = Column(
        String(36),
        nullable=False,
        unique=False,
        index=True)
    
    lock_time = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    lock_owner = Column(
        String(512),
        nullable=True)

class LockedException(Exception):
    def __init__(self, target, *args, **kwargs):
        self.target = target

    def __str__(self):
        return f"LockedException: unable to get lock on {self.target} uuid {self.target.uuid}"

class Malware(Base):

    __tablename__ = 'malware'

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, index=True)
    threats = relationship("Threat", passive_deletes=True, passive_updates=True)

class Threat(Base):

    __tablename__ = 'malware_threat_mapping'

    malware_id = Column(Integer, ForeignKey('malware.id'), primary_key=True)
    type = Column(Enum('UNKNOWN','KEYLOGGER','INFOSTEALER','DOWNLOADER','BOTNET','RAT','RANSOMWARE','ROOTKIT','FRAUD','CUSTOMER_THREAT','WIPER','TRAFFIC_DIRECTION_SYSTEM'), primary_key=True, nullable=False)

    def __str__(self):
        return self.type

class ObservableMapping(Base):

    __tablename__ = 'observable_mapping'

    observable_id = Column(
        Integer,
        ForeignKey('observables.id'),
        primary_key=True)

    alert_id = Column(
        Integer,
        ForeignKey('alerts.id'),
        primary_key=True)

    alert = relationship('Alert', backref='observable_mappings')
    observable = relationship('Observable', backref='observable_mappings')

class ObservableRemediationMapping(Base):

    __tablename__ = 'observable_remediation_mapping'

    observable_id = Column(
        Integer,
        ForeignKey('observables.id'),
        primary_key=True)

    remediation_id = Column(
        Integer,
        ForeignKey('remediation.id'),
        primary_key=True)

    observable = relationship('Observable', backref='observable_remediation_mappings')
    remediation = relationship('Remediation', backref='observable_remediation_mappings')

# this is used to automatically map tags to observables
# same as the etc/site_tags.csv really, just in the database
class ObservableTagMapping(Base):
    
    __tablename__ = 'observable_tag_mapping'

    observable_id = Column(
        Integer,
        ForeignKey('observables.id'),
        primary_key=True)

    tag_id = Column(
        Integer,
        ForeignKey('tags.id'),
        primary_key=True)

    observable = relationship('Observable', backref='observable_tag_mapping')
    tag = relationship('Tag', backref='observable_tag_mapping')


# this is used to map what observables had what tags in what alerts
# not to be confused with ObservableTagMapping (see above)
# I think this is what I had in mind when I originally created ObservableTagMapping
# but I was missing the alert_id field
# that table was later repurposed to automatically map tags to observables

class ObservableTagIndex(Base):

    __tablename__ = 'observable_tag_index'

    observable_id = Column(
        Integer,
        ForeignKey('observables.id'),
        primary_key=True)

    tag_id = Column(
        Integer,
        ForeignKey('tags.id'),
        primary_key=True)

    alert_id = Column(
        Integer,
        ForeignKey('alerts.id'),
        primary_key=True)

    observable = relationship('Observable', backref='observable_tag_index')
    tag = relationship('Tag', backref='observable_tag_index')
    alert = relationship('Alert', backref='observable_tag_index')

class TagMapping(Base):

    __tablename__ = 'tag_mapping'

    tag_id = Column(
        Integer,
        ForeignKey('tags.id'),
        primary_key=True)

    alert_id = Column(
        Integer,
        ForeignKey('alerts.id'),
        primary_key=True)

    alert = relationship('Alert', backref='tag_mapping', overlaps="tag_mappings")
    tag = relationship('Tag', backref='tag_mapping')

class CompanyMapping(Base):

    __tablename__ = 'company_mapping'

    event_id = Column(Integer, ForeignKey('events.id'), primary_key=True)
    company_id = Column(Integer, ForeignKey('company.id'), primary_key=True)
    company = relationship("Company")

    @property
    def name(self):
        return self.company.name

class EventMapping(Base):

    __tablename__ = 'event_mapping'

    event_id = Column(Integer, ForeignKey('events.id'), primary_key=True)
    alert_id = Column(Integer, ForeignKey('alerts.id'), primary_key=True)

    alert = relationship('Alert', backref='event_mapping')
    event = relationship('Event', backref='alert_mappings')

class EventTagMapping(Base):
    __tablename__ = 'event_tag_mapping'

    event_id = Column(
            Integer,
            ForeignKey('events.id'),
            primary_key=True)

    tag_id = Column(
            Integer,
            ForeignKey('tags.id'),
            primary_key=True)

    event = relationship('Event', backref='event_tag_mapping')
    tag = relationship('Tag', backref='event_tag_mapping')



class MalwareMapping(Base):

    __tablename__ = 'malware_mapping'

    event_id = Column(Integer, ForeignKey('events.id'), primary_key=True)
    malware_id = Column(Integer, ForeignKey('malware.id'), primary_key=True)
    malware = relationship("Malware")

    @property
    def threats(self):
        return self.malware.threats

    @property
    def name(self):
        return self.malware.name

class Message(Base):

    __tablename__ = 'messages'

    id = Column(
        BigInteger,
        primary_key=True)

    content = Column(
        String,
        nullable=False)

class MessageRouting(Base):

    __tablename__ = 'message_routing'

    id = Column(
        BigInteger,
        primary_key=True)

    message_id = Column(
        BigInteger,
        ForeignKey('messages.id'),
        nullable=False)

    message = relationship('Message', foreign_keys=[message_id], backref='routing')

    route = Column(
        String,
        nullable=False)

    destination = Column(
        String,
        nullable=False)

    lock = Column(
        String,
        nullable=True)

    lock_time = Column(
        DateTime,
        nullable=True)

class Nodes(Base):

    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    name = Column(String(1024), nullable=False)
    location = Column(String(1024), nullable=False)

class Observable(Base):

    __tablename__ = 'observables'

    id = Column(
        Integer,
        primary_key=True)

    type = Column(
        String(64),
        nullable=False)

    sha256 = Column(
        VARBINARY(32),
        nullable=False)

    value = Column(
        BLOB,
        nullable=False)

    for_detection = Column(
        BOOLEAN,
        nullable=False,
        default=False)

    expires_on = Column(
        DateTime,
        nullable=True)

    fa_hits = Column(
        Integer,
        nullable=True)

    enabled_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True)

    detection_context = Column(
        Text,
        nullable=True)

    batch_id = Column(
        String(36),
        nullable=True)

    @property
    def display_value(self):
        return self.value.decode('utf8', errors='ignore')

    tags = relationship('ObservableTagIndex', passive_deletes=True, passive_updates=True, overlaps="observable,observable_tag_index")
    enabled_by_user = relationship('User')

    @property
    def json(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": base64.b64encode(self.value).decode(),
            "sha256": self.sha256.hex(),
            "for_detection": self.for_detection == 1,
            "expires_on": self.expires_on,
            "fa_hits": self.fa_hits,
            "enabled_by": self.enabled_by_user.json if self.enabled_by else None,
            "detection_context": self.detection_context,
            "batch_id": self.batch_id, 
        }

class PersistenceSource(Base):

    __tablename__ = 'persistence_source'
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True)

    name = Column(
        String(256),
        nullable=False)

class Persistence(Base):

    __tablename__ = 'persistence'

    id = Column(
        BigInteger,
        primary_key=True,
        autoincrement=True)

    source_id = Column(
        Integer,
        ForeignKey('persistence_source.id'),
    )

    permanent = Column(
        Integer,
        nullable=False,
        server_default=text('0'))

    uuid = Column(
        String(512),
        nullable=False)

    value = Column(
        BLOB(),
        nullable=True)

    last_update = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    created_at = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

class Remediation(Base):

    __tablename__ = 'remediation'

    id = Column(
        Integer,
        primary_key=True)

    type = Column(
        String,
        nullable=False,
        default='email')

    action = Column(
        Enum('remove', 'restore'),
        nullable=False,
        default='remove')

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    update_time = Column(
        TIMESTAMP, 
        nullable=True, 
        index=True,
        server_default=None)

    user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=False)

    user = relationship('User', backref='remediations')

    key = Column(
        String,
        nullable=False)

    restore_key = Column(
        String,
        nullable=True,
        default=None)

    result = Column(
        String,
        nullable=True)

    _results = None

    @property
    def results(self):
        if self._results is None:
            try:
                if self.result is None:
                    self._results = {}
                else:
                    self._results = json.loads(self.result)
            except:
                self._results = {'remediator_deprecated': {'complete': True, 'success':self.successful, 'result':self.result}}
        return self._results

    comment = Column(
        String,
        nullable=True)
    
    @property
    def alert_uuids(self):
        """If the comment is a comma separated list of alert uuids, then that list is provided here as a property.
           Otherwise this returns an emtpy list."""
        result = []
        if self.comment is None:
            return result

        for _uuid in self.comment.split(','):
            try:
                validate_uuid(_uuid)
                result.append(_uuid)
            except ValueError:
                continue

        return result

    successful = Column(
        BOOLEAN,
        nullable=True,
        default=None)

    lock = Column(
        String(36), 
        nullable=True)

    lock_time = Column(
        DateTime,
        nullable=True)

    status = Column(
        Enum('NEW', 'IN_PROGRESS', 'COMPLETED'),
        nullable=False,
        default='NEW')

    @property
    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'action': self.action,
            'insert_date': self.insert_date,
            'user_id': self.user_id,
            'key': self.key,
            'result': self.result,
            'comment': self.comment,
            'successful': self.successful,
            'company_id': self.company_id,
            'status': self.status,
        }

    def __str__(self):
        return f"Remediation: {self.action} - {self.type} - {self.status} - {self.key} - {self.result}"

class Tag(_Tag, Base):
    
    __tablename__ = 'tags'

    id = Column(
        Integer,
        primary_key=True)

    name = Column(
        String(256),
        nullable=False)

    @property
    def display(self):
        tag_name = self.name.split(':')[0]
        if tag_name in get_config()['tags'] and get_config()['tags'][tag_name] == "special":
            return False
        return True

    @property
    def style(self):
        tag_name = self.name.split(':')[0]
        if tag_name in get_config()['tags']:
            return get_config()['tag_css_class'][get_config()['tags'][tag_name]]
        else:
            return 'label-default'

    #def __init__(self, *args, **kwargs):
        #super(saq.database.Tag, self).__init__(*args, **kwargs)

    @reconstructor
    def init_on_load(self, *args, **kwargs):
        super(Tag, self).__init__(*args, **kwargs)

class User(UserMixin, Base):

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True)
    email = Column(String(64), unique=True, index=True)
    password_hash = Column(String(256))
    omniscience = Column(Integer, nullable=False, default=0)
    timezone = Column(String(512))
    display_name = Column(String(1024))
    queue = Column(
        String(64),
        nullable=False,
        default=QUEUE_DEFAULT)
    enabled = Column(Boolean, unique=False, default=True)
    apikey_hash = Column(String(64), nullable=True, default=None)
    apikey_encrypted = Column(BLOB, nullable=True, default=None)

    def __str__(self):
        return self.username

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "timezone": self.timezone,
            "display_name": self.display_name,
            "default_queue": self.queue,
            "enabled": self.enabled == 1,
        }

    @property
    def apikey_decrypted(self):
        if self.apikey_encrypted is None:
            return None

        try:
            decrypted = decrypt_chunk(self.apikey_encrypted)
            return decrypted.decode()
        except Exception as e:
            logging.error("unable to decrypt api key: {e}")

        return None

    @property
    def gui_display(self):
        """Returns the textual representation of this user in the GUI.
           If the user has a display_name value set then that is returned.
           Otherwise, the username is returned."""

        if self.display_name is not None:
            return self.display_name

        return self.username

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, value):
        self.password_hash = generate_password_hash(value)

    def verify_password(self, value):
        return check_password_hash(self.password_hash, value)

Owner = aliased(User)
DispositionBy = aliased(User)
RemediatedBy = aliased(User)

class Comment(Base):

    __tablename__ = 'comments'

    comment_id = Column(
        Integer,
        primary_key=True)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True,
        server_default=text('CURRENT_TIMESTAMP'))

    user_id = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=False)

    uuid = Column(
        String(36), 
        ForeignKey('alerts.uuid'),
        nullable=False)

    comment = Column(Text)

    # many to one
    user = relationship('User', backref='comments')


class Workload(Base):

    __tablename__ = 'workload'

    id = Column(
        Integer,
        primary_key=True)

    uuid = Column(
        String(36), 
        nullable=False,
        unique=True)

    node_id = Column(
        Integer,
        nullable=False, 
        index=True)

    analysis_mode = Column(
        String(256),
        nullable=False,
        index=True)

    insert_date = Column(
        TIMESTAMP, 
        nullable=False, 
        index=True)

    company_id = Column(
        Integer,
        ForeignKey('company.id'),
        nullable=True)

    company = relationship('Company', foreign_keys=[company_id])

    storage_dir = Column(
        String(1024), 
        unique=True, 
        nullable=False)

# NOTE there is no database relationship between these tables
Alert.workload = relationship('Workload', foreign_keys=[Alert.uuid], primaryjoin='Workload.uuid == Alert.uuid')
Alert.delayed_analysis = relationship('DelayedAnalysis', foreign_keys=[Alert.uuid], primaryjoin='DelayedAnalysis.uuid == Alert.uuid', overlaps="workload")
Alert.lock = relationship('Lock', foreign_keys=[Alert.uuid], primaryjoin='Lock.uuid == Alert.uuid', overlaps="delayed_analysis,workload")
Alert.nodes = relationship('Nodes', foreign_keys=[Alert.location], primaryjoin='Nodes.name == Alert.location')
# vim: sw=4:ts=4:et
#
# Persistence
# Functionality to store data in long term storage external to the system.
#

from datetime import datetime
import logging
import pickle
from typing import Any, Optional

from saq.database import ( 
    Persistence, 
    PersistenceSource, 
    execute_with_retry,
    get_db
)
from saq.database.pool import get_db_connection

from sqlalchemy.exc import NoResultFound
from sqlalchemy import and_


def truncate_key(key_name):
    """The Persistence database uuid column is limited to 512 in length. This returns a truncated key."""
    return str(key_name)[0:512]

class Persistable:
    def __init__(self):
        self.persistence_source = None
        self.persistence_key_mapping = {}

    def register_persistence_source(self, source_name):
        persistence_source = get_db().query(PersistenceSource).filter(
            PersistenceSource.name == source_name).first()
        
        if persistence_source is None:
            logging.info(f"registering persistence source {source_name}")
            get_db().add(PersistenceSource(name=source_name))
            get_db().commit()

            persistence_source = get_db().query(PersistenceSource).filter(
                PersistenceSource.name == source_name).first()

            if persistence_source is None:
                logging.critical(f"unable to create persistence source for {source_name}")
                return None

        get_db().expunge(persistence_source)
        self.persistence_source = persistence_source
        return self.persistence_source

    def save_persistent_key(self, key_name):
        """Creates a new persistent key with no value recorded. The key must not already exist."""
        key_name = truncate_key(key_name)
        self.save_persistent_data(key_name)

    def save_persistent_data(self, key_name: str, key_value: Optional[Any]=None):
        """Creates a new persistent key with the given value recorded. The key must not already exist."""
        if key_value is not None:
            key_value = pickle.dumps(key_value)

        key_name = truncate_key(key_name)

        with get_db_connection() as db:
            c = db.cursor()
            execute_with_retry(db, c, """
INSERT INTO persistence ( 
    source_id, 
    uuid,
    value
) VALUES ( %s, %s, %s )
ON DUPLICATE KEY UPDATE value = %s, last_update = CURRENT_TIMESTAMP""", (self.persistence_source.id, key_name, key_value, key_value),
            commit=True)

    def load_persistent_data(self, key_name):
        """Returns the value of the persistent key by name. Raises an exception if the key does not exist."""

        key_name = truncate_key(key_name)

        try:
            persistence = get_db().query(Persistence).filter(Persistence.source_id == self.persistence_source.id,
                                                           Persistence.uuid == key_name).one()
        except NoResultFound:
            raise KeyError(key_name)

        if persistence.value is None:
            return None

        return pickle.loads(persistence.value)

    def persistent_data_exists(self, key_name):
        """Returns True if the given key exists, False otherwise."""

        key_name = truncate_key(key_name)

        persistence = get_db().query(Persistence).filter(Persistence.source_id == self.persistence_source.id,
                                                       Persistence.uuid == key_name).first()
        return persistence is not None

    def delete_persistent_key(self, key_name):
        """Deletes the given persistence key."""

        key_name = truncate_key(key_name)

        get_db().execute(Persistence.__table__.delete().where(and_(Persistence.source_id == self.persistence_source.id,
                                                            Persistence.uuid == key_name)))
        get_db().commit()

    def delete_expired_persistent_keys(self, expiration_timedelta, unmodified_expiration_timedelta):
        """Deletes all expired persistence keys."""
        expiration_date = datetime.now() - expiration_timedelta
        unmodified_expiration_date = datetime.now() - unmodified_expiration_timedelta
        # we split this up into two operations so we can use the indexes built for them (idx_p_clear_expired_1, idx_p_clear_expired_2)
        get_db().execute(Persistence.__table__.delete().where(and_(Persistence.source_id == self.persistence_source.id,
                                                            Persistence.permanent == 0,
                                                            Persistence.created_at < expiration_date)))
        get_db().execute(Persistence.__table__.delete().where(and_(Persistence.source_id == self.persistence_source.id,
                                                            Persistence.permanent == 0,
                                                            Persistence.last_update < unmodified_expiration_date)))
        get_db().commit()
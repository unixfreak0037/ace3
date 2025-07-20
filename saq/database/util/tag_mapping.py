import logging
from typing import TYPE_CHECKING
from sqlalchemy import and_, func
from saq.database.model import Event, EventTagMapping, Observable, ObservableTagMapping, Tag
from saq.database.pool import get_db
from sqlalchemy.exc import NoResultFound

from saq.database.util.sync import sync_observable

if TYPE_CHECKING:
    from saq.observables.base import Observable as ObservableType


#def add_observable_tag_mapping(o_type, o_value, o_sha256, tag):
def add_observable_tag_mapping(observable: "ObservableType", tag: str) -> bool:
    try:
        tag = get_db().query(Tag).filter(Tag.name == tag).one()
    except NoResultFound as e:
        get_db().execute(Tag.__table__.insert().values(name=tag))
        get_db().commit()
        tag = get_db().query(Tag).filter(Tag.name == tag).one()

    db_observable = get_db().query(Observable).filter(Observable.type==observable.type, Observable.sha256==func.UNHEX(observable.sha256_hash)).one_or_none()

    #if o_sha256 is not None:
        #try:
            #observable = get_db().query(Observable).filter(Observable.type==o_type, 
                                                                      #Observable.sha256==func.UNHEX(o_sha256)).one()
        #except NoResultFound as e:
            #if o_value is None:
                #logging.warning(f"observable type {o_type} sha256 {o_sha256} cannot be found for mapping")
                #return False

    if db_observable is None:
        db_observable = sync_observable(observable)
        get_db().commit()

    try:
        mapping = get_db().query(ObservableTagMapping).filter(ObservableTagMapping.observable_id == db_observable.id,
                                                            ObservableTagMapping.tag_id == tag.id).one()
        get_db().commit()
        return True

    except NoResultFound as e:
        get_db().execute(ObservableTagMapping.__table__.insert().values(observable_id=db_observable.id, tag_id=tag.id))
        get_db().commit()
        return True

def remove_observable_tag_mapping(observable: "ObservableType", tag: str) -> bool:
    tag = get_db().query(Tag).filter(Tag.name == tag).one_or_none()
    if tag is None:
        logging.warning(f"tag {tag} cannot be found to remove tag mapping")
        return False

    db_observable = get_db().query(Observable).filter(Observable.type == observable.type, Observable.sha256 == func.UNHEX(observable.sha256_hash)).one_or_none()
    
    if db_observable is None:
        logging.warning(f"observable {observable} cannot be found to remove tag mapping")
        return False

    get_db().execute(ObservableTagMapping.__table__.delete().where(and_(ObservableTagMapping.observable_id == db_observable.id,
                                                                 ObservableTagMapping.tag_id == tag.id)))
    get_db().commit()
    return True

def add_event_tag_mapping(event_id: str, tag: str) -> bool:
    """ "Adds" specified tag to given event by adding new entry in Tag table (if does not already exist) and then and EventTagMapping/
        Args:
            event_id: A string containing the ID of the event to add the tag to
            tag: A string containing the name (value) of the tag to be added
        Returns:
            bool: A bool specifying whether the tag was successfully added to the event.
    """

    try:
        tag = get_db().query(Tag).filter(Tag.name == tag).one()
    except NoResultFound:
        get_db().execute(Tag.__table__.insert().values(name=tag))
        get_db().commit()
        tag = get_db().query(Tag).filter(Tag.name == tag).one()

    event = None
    try:
        event = get_db().query(Event).filter(Event.id == event_id).one()
    except NoResultFound:
        if event is None:
            logging.warning(f"event {event_id} cannot be found for mapping")
            return False

    if event is None:
        return False

    try:
        get_db().query(EventTagMapping).filter(EventTagMapping.event_id == event.id,
                                             EventTagMapping.tag_id == tag.id).one()
        get_db().commit()
        return True

    except NoResultFound as e:
        get_db().execute(EventTagMapping.__table__.insert().values(event_id=event.id, tag_id=tag.id))
        get_db().commit()
        return True
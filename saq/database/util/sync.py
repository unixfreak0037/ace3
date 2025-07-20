from sqlalchemy import func
from saq.analysis.observable import get_observable_type_expiration_time
from saq.database.pool import get_db
from saq.database.retry import retry


@retry
def sync_observable(observable):
    """Syncs the given observable to the database by inserting a row in the observables table if it does not currently exist.
       Returns the existing or newly created saq.database.Observable entry for the corresponding row."""
    from saq.database.model import Observable
    existing_observable = get_db().query(Observable).filter(Observable.type == observable.type,
                                                                       Observable.sha256 == func.UNHEX(observable.sha256_hash)).first()
    if existing_observable is None:
        # XXX assuming all observables are encodable in utf-8 is probably wrong
        # XXX we could have some kind of binary data, or an intentionally corrupt value
        # XXX in which case we'd lose the actual value of the data here
        existing_observable = Observable(type=observable.type, 
                                         value=observable.value.encode('utf8', errors='ignore'), 
                                         sha256=func.UNHEX(observable.sha256_hash),
                                         expires_on=get_observable_type_expiration_time(observable.type))
        get_db().add(existing_observable)
        get_db().flush()

    return existing_observable
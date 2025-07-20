from typing import Optional
from saq.analysis.observable import get_observable_type_expiration_time
from saq.analysis.root import RootAnalysis
from saq.constants import ANALYSIS_MODE_DISPOSITIONED, DISPOSITION_IGNORE
from saq.database.model import Alert, Observable, ObservableMapping
from saq.database.pool import get_db, get_db_connection
from saq.disposition import get_malicious_dispositions


def ALERT(root: RootAnalysis) -> Alert:
    """Converts the given RootAnalysis object to an Alert by inserting it into the database. Returns the (detached) Alert object."""
    alert = Alert.create_from_root_analysis(root)
    alert.sync()
    return alert

def get_alert_by_uuid(uuid: str) -> Optional[Alert]:
    """Given a UUID, this function will return the Alert object from the database, or None if it does not exist."""
    return get_db().query(Alert).filter(Alert.uuid == uuid).one_or_none()

def refresh_observable_expires_on(alert_uuids: list[str], nullify: bool = False) -> None:
    """Given a list of alert UUIDs, this function will check the config for any observable time deltas and will
    update each observable's expires_on database value accordingly. It will only update expires_on datetimes if they
    are not currently set to Null, which allows for setting observables to never expire.
        :param alert_uuids: A list of UUIDs of Alert objects
        :param nullify: Boolean setting for whether or not to set the observables' expires_on to Null"""

    # Get a list of observable IDs and their type that need to have their expires_on updated.
    query = get_db().query(Observable.id, Observable.type) \
        .join(ObservableMapping, Observable.id == ObservableMapping.observable_id) \
        .join(Alert, ObservableMapping.alert_id == Alert.id) \
        .filter(Alert.uuid.in_(alert_uuids)) \
        .filter(Observable.expires_on.isnot(None))

    # Transform the results into a dictionary where the keys are the observable types and the values are lists
    # of the observable IDs that need to be updated.
    results = query.all()
    observables = dict()
    for result in results:
        if result[1] not in observables:
            observables[result[1]] = []

        observables[result[1]].append(result[0])

    # Update the expires_on times for each of the observable types.
    else:
        for observable_type in observables:
            expires_on = None if nullify else get_observable_type_expiration_time(observable_type)

            get_db().query(Observable) \
                .filter(Observable.id.in_(observables[observable_type])) \
                .update({Observable.expires_on: expires_on}, synchronize_session=False)

            get_db().commit()

def set_dispositions(alert_uuids, disposition, user_id, user_comment=None):
    """Utility function to the set disposition of many Alerts at once. Part of the dispositioning process is to also
    update the expires_on datetime of the observables in the alerts.
       :param alert_uuids: A list of UUIDs of Alert objects to set.
       :param disposition: The disposition to set the Alerts.
       :param user_id: The id of the User that is setting the disposition.
       :param user_comment: Optional comment the User is providing as part of the disposition."""

    # If the disposition is malicious, refresh the expires_on datetime for all of the observables in the alerts.
    if disposition in get_malicious_dispositions():
        refresh_observable_expires_on(alert_uuids, nullify=False)

    with get_db_connection() as db:
        c = db.cursor()
        # update dispositions
        uuid_placeholders = ','.join(['%s' for _ in alert_uuids])
        sql = f"""UPDATE alerts SET 
                      disposition = %s, disposition_user_id = %s, disposition_time = NOW(),
                      owner_id = IF(owner_id IS NULL, %s, owner_id), owner_time = IF(owner_time IS NULL, NOW(), owner_time)
                  WHERE 
                      (disposition IS NULL OR disposition != %s) AND uuid IN ( {uuid_placeholders} )"""
        parameters = [disposition, user_id, user_id, disposition]
        parameters.extend(alert_uuids)
        c.execute(sql, parameters)
        
        # add the comment if it exists
        if user_comment:
            for uuid in alert_uuids:
                c.execute("""
                          INSERT INTO comments ( user_id, uuid, comment ) 
                          VALUES ( %s, %s, %s )""", ( user_id, uuid, user_comment))

        # now we need to insert each of these alert back into the workload
        # if we are setting the disposition to anything but IGNORE
        if disposition != DISPOSITION_IGNORE:
            sql = f"""
INSERT IGNORE INTO workload ( uuid, node_id, analysis_mode, insert_date, company_id, storage_dir ) 
SELECT 
    alerts.uuid, 
    nodes.id,
    %s, 
    NOW(),
    alerts.company_id, 
    alerts.storage_dir 
FROM 
    alerts JOIN nodes ON alerts.location = nodes.name
WHERE 
    uuid IN ( {uuid_placeholders} )"""
            params = [ ANALYSIS_MODE_DISPOSITIONED ]
            params.extend(alert_uuids)
            c.execute(sql, tuple(params))

        db.commit()
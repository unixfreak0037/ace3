from typing import Optional
from saq.analysis.disposition_history import DispositionHistory
from saq.analysis.observable import Observable
from saq.constants import F_FILE
from saq.database.pool import get_db_connection


def observable_is_set_for_detection(observable: Observable) -> bool:
    """Returns True if the observable is set for detection, False otherwise."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT for_detection FROM observables WHERE sha256 = UNHEX(%s)", (observable.sha256_hash,))
        result = cursor.fetchone()
        return bool(result[0]) if result else False

def observable_set_for_detection(observable: Observable, value: bool):
    """Sets the observable for detection."""
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("UPDATE observables SET for_detection = %s WHERE sha256 = UNHEX(%s)", (value, observable.sha256_hash))
        if cursor.rowcount == 0:
            cursor.execute("INSERT INTO observables (`type`, `value`, `sha256`, `for_detection`) VALUES (%s, %s, UNHEX(%s), %s)", (observable.type, observable.value, observable.sha256_hash, value))

        db.commit()

def get_observable_disposition_history(observable: Observable) -> Optional[DispositionHistory]:
    """Returns a DispositionHistory object if self.obj is an Observable, None otherwise."""
    if observable.whitelisted:
        return None

    result = DispositionHistory(observable)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""
    SELECT 
        a.disposition, COUNT(*) 
    FROM 
        observables o JOIN observable_mapping om ON o.id = om.observable_id
        JOIN alerts a ON om.alert_id = a.id
    WHERE 
        o.type = %s AND 
        o.sha256 = UNHEX(%s) AND
        a.alert_type != 'faqueue' AND
        a.disposition != 'UNKNOWN'
    GROUP BY a.disposition""", (observable.type, observable.sha256_hash))

        for row in cursor:
            disposition, count = row
            result[disposition] = count

    return result

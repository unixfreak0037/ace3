from uuid import uuid4
import pytest

from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry

@pytest.mark.integration
def test_execute_with_retry():
    # simple single statement transaction
    with get_db_connection() as db:
        cursor = db.cursor()
        execute_with_retry(db, cursor, [ 'SELECT 1' ], [ tuple() ])
        db.commit()

    # multi statement transaction
    _uuid = str(uuid4())
    _lock_uuid = str(uuid4())
    with get_db_connection() as db:
        cursor = db.cursor()
        execute_with_retry(db, cursor, [ 
            'INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )',
            'UPDATE locks SET lock_uuid = %s WHERE uuid = %s',
            'DELETE FROM locks WHERE uuid = %s',
        ], [ 
            (_uuid,),
            (_lock_uuid, _uuid),
            (_uuid,),
        ])
        db.commit()

@pytest.mark.integration
def test_execute_with_retry_commit():
    _uuid = str(uuid4())
    _lock_uuid = str(uuid4())

    # simple insert statement with commit option
    with get_db_connection() as db:
        cursor = db.cursor()
        execute_with_retry(db, cursor, 'INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )', (_uuid,), commit=True)

    # check it on another connection
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uuid FROM locks WHERE uuid = %s", (_uuid,))
        assert cursor.fetchone() is not None

    _uuid = str(uuid4())
    _lock_uuid = str(uuid4())

    # and then this one should fail since we did not commit it
    with get_db_connection() as db:
        cursor = db.cursor()
        execute_with_retry(db, cursor, 'INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )', (_uuid,), commit=False)

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("SELECT uuid FROM locks WHERE uuid = %s", (_uuid,))
        assert cursor.fetchone() is None
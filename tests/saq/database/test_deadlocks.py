import threading
import time
from uuid import uuid4
import pymysql
import pytest

from saq.database.model import User
from saq.database.pool import get_db, get_db_connection
from saq.database.retry import execute_with_retry, retry_function_on_deadlock, retry_sql_on_deadlock
from tests.saq.helpers import log_count

@pytest.mark.skip("fix me")
@pytest.mark.system
def test_deadlock():
    # make sure we can always generate a deadlock
    _uuid = str(uuid4())
    _lock_uuid = str(uuid4())

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO locks ( uuid, lock_uuid, lock_time ) VALUES ( %s, %s, NOW() )", ( _uuid, _lock_uuid ))
        db.commit()

    # one of these threads will get a deadlock
    def _t1():
        _uuid = str(uuid4())
        _lock_uuid = str(uuid4())
        try:
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )", (_uuid,))
                # wait for signal to continue
                time.sleep(2)
                cursor.execute("UPDATE locks SET lock_owner = 'whatever'")
                db.commit()
        except pymysql.err.OperationalError as e:
            if e.args[0] == 1213 or e.args[0] == 1205:
                deadlock_event.set()

    def _t2():
        _uuid = str(uuid4())
        _lock_uuid = str(uuid4())
        try:
            with get_db_connection() as db:
                cursor = db.cursor()
                cursor.execute("UPDATE locks SET lock_owner = 'whatever'")
                # wait for signal to continue
                time.sleep(2)
                cursor.execute("INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )", (_uuid,))
                db.commit()
        except pymysql.err.OperationalError as e:
            if e.args[0] == 1213 or e.args[0] == 1205:
                deadlock_event.set()

    deadlock_event = threading.Event()

    t1 = threading.Thread(target=_t1)
    t2 = threading.Thread(target=_t2)

    t1.start()
    t2.start()

    assert deadlock_event.wait(5)
    t1.join(5)
    t2.join(5)

    assert not t1.is_alive()
    assert not t2.is_alive()

@pytest.mark.skip(reason="fix me")
@pytest.mark.system
def test_retry_on_deadlock():
    # make sure our code to retry failed transactions on deadlocks
    _uuid = str(uuid4())
    _lock_uuid = str(uuid4())

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("INSERT INTO locks ( uuid, lock_uuid, lock_time ) VALUES ( %s, %s, NOW() )", ( _uuid, _lock_uuid ))
        db.commit()

    # one of these threads will get a deadlock
    def _t1():
        _uuid = str(uuid4())
        _lock_uuid = str(uuid4())
        try:
            with get_db_connection() as db:
                c = db.cursor()
                execute_with_retry(db, c, "INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )", (_uuid,))
                # wait for signal to continue
                time.sleep(2)
                execute_with_retry(db, c, "UPDATE locks SET lock_owner = 'whatever'")
                db.commit()
        except pymysql.err.OperationalError as e:
            if e.args[0] == 1213 or e.args[0] == 1205:
                deadlock_event.set()

    def _t2():
        _uuid = str(uuid4())
        _lock_uuid = str(uuid4())
        try:
            with get_db_connection() as db:
                c = db.cursor()
                execute_with_retry(db, c, "UPDATE locks SET lock_owner = 'whatever'")
                # wait for signal to continue
                time.sleep(2)
                execute_with_retry(db, c, "INSERT INTO locks ( uuid, lock_time ) VALUES ( %s, NOW() )", (_uuid,))
                db.commit()
        except pymysql.err.OperationalError as e:
            if e.args[0] == 1213 or e.args[0] == 1205:
                deadlock_event.set()

    deadlock_event = threading.Event()

    t1 = threading.Thread(target=_t1)
    t2 = threading.Thread(target=_t2)

    t1.start()
    t2.start()

    assert not deadlock_event.wait(5)
    t1.join(5)
    t2.join(5)

    assert not t1.is_alive()
    assert not t2.is_alive()

    assert log_count('deadlock detected') == 1


@pytest.mark.skip(reason="Now this one is failing too -- need to revisit this soon.")
@pytest.mark.system
def test_retry_function_on_deadlock():

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO users ( username, email ) VALUES ( 'user0', 'user0@localhost' )")
        cursor.execute("INSERT INTO users ( username, email ) VALUES ( 'user1', 'user1@localhost' )")
        db.commit()

    lock_user0 = threading.Event()
    lock_user1 = threading.Event()

    def _t1():
        # acquire lock on user0
        get_db().execute(User.__table__.update().where(User.username == 'user0').values(email='user0@t1'))
        lock_user0.set()
        # wait for lock on user1
        lock_user1.wait(5)
        time.sleep(2)
        # this should fire a deadlock
        get_db().execute(User.__table__.update().where(User.username == 'user1').values(email='user1@t1'))
        get_db().commit()

    def _t2():
        with get_db_connection() as db:
            cursor = db.cursor()
            lock_user0.wait(5)
            # acquire lock on user1
            cursor.execute("UPDATE users SET email = 'user1@t2' WHERE username = 'user1'")
            lock_user1.set()
            # this will block waiting for lock on user0
            cursor.execute("UPDATE users SET email = 'user0@t2' WHERE username = 'user0'")
            db.commit()

    t1 = threading.Thread(target=retry_function_on_deadlock, args=(_t1,))
    t1.start()
    t2 = threading.Thread(target=_t2)
    t2.start()

    t1.join(5)
    t2.join(5)

    assert log_count('DEADLOCK STATEMENT') == 1
    assert get_db().query(User).filter(User.email == 'user0@t1', User.username == 'user0').first()
    assert get_db().query(User).filter(User.email == 'user1@t1', User.username == 'user1').first()

@pytest.mark.skip(reason="Can't seem to get this one to always fire.")
@pytest.mark.system
def test_retry_sql_on_deadlock():

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("INSERT INTO users ( username, email ) VALUES ( 'user0', 'user0@localhost' )")
        cursor.execute("INSERT INTO users ( username, email ) VALUES ( 'user1', 'user1@localhost' )")
        db.commit()

    lock_user0 = threading.Event()
    lock_user1 = threading.Event()

    def _t1():
        session = get_db()
        # acquire lock on user0
        retry_sql_on_deadlock(User.__table__.update().where(User.username == 'user0')
                                                        .values(email='user0@_t1'),
                                session=session)
        lock_user0.set()
        # wait for lock on user1
        lock_user1.wait(5)
        time.sleep(2)
        # this should fire a deadlock
        # 3/8/2019 - used to expect the deadlock here, but it can also happen in the first statement of _t2
        retry_sql_on_deadlock(User.__table__.update().where(User.username == 'user1')
                                                        .values(email='user1@_t1'),
                                session=session,
                                commit=True) 
    def _t2():
        with get_db_connection() as db:
            c = db.cursor()
            lock_user0.wait(5)
            # acquire lock on user1
            execute_with_retry(db, c, "UPDATE users SET email = 'user1@_t2' WHERE username = 'user1'")
            lock_user1.set()
            # this will block waiting for lock on user0
            execute_with_retry(db, c, "UPDATE users SET email = 'user0@_t2' WHERE username = 'user0'")
            db.commit()

    t1 = threading.Thread(target=_t1)
    t1.start()
    t2 = threading.Thread(target=_t2)
    t2.start()

    t1.join(5)
    t2.join(5)

    assert log_count('DEADLOCK STATEMENT') == 1
    assert get_db().query(User).filter(User.email == 'user0@_t2', User.username == 'user0').first()
    assert get_db().query(User).filter(User.email == 'user1@_t1', User.username == 'user1').first()
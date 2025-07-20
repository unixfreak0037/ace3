from flask import url_for
import pytest

from app.application import create_app
from app.models import User
from saq.constants import QUEUE_DEFAULT
from saq.database.pool import get_db_connection

@pytest.fixture(scope="function")
def analyst(global_setup):

    u = User()
    u.username = "john"
    u.email = "john@localhost"
    u.display_name = "john"
    u.queue = QUEUE_DEFAULT
    u.timezone = "Etc/UTC"
    u.password = "password"

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("""INSERT INTO users ( username, email, password_hash, timezone, display_name, queue ) VALUES ( %s, %s, %s, %s, %s, %s )""", (
            u.username, u.email, u.password_hash, u.timezone, u.display_name, u.queue ))
        user_id = cursor.lastrowid
        db.commit()

    yield user_id

    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        db.commit()

@pytest.fixture(autouse=True, scope="function")
def app(global_setup):
    flask_app = create_app(testing=True)
    flask_app.config.update({
        "TESTING": True,
    })

    app_context = flask_app.test_request_context()                      
    app_context.push()                           

    yield flask_app

@pytest.fixture
def web_client(app, analyst):
    with app.test_client() as client:
        login_result = client.post(url_for("auth.login"), data={
            "username": "john",
            "password": "password",
        })
        yield client

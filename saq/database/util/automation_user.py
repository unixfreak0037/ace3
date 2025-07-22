import logging
import sys
from saq.constants import G_AUTOMATION_USER_ID
from saq.database.model import User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user
from saq.environment import g_int, set_g
import secrets


def initialize_automation_user():
    # get the id of the ace automation account
    try:
        set_g(G_AUTOMATION_USER_ID, get_db().query(User).filter(User.username == 'ace').one().id)
        get_db().remove()
    except Exception as e:
        # if the account is missing go ahead and create it
        random_password = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+') for _ in range(16))
        user = add_user(
            username='ace',
            email='ace@localhost',
            display_name='automation',
            password=random_password,
            queue='default',
            timezone='Etc/UTC'
        )

        try:
            set_g(G_AUTOMATION_USER_ID, get_db().query(User).filter(User.username == 'ace').one().id)
        except Exception as e:
            logging.error(f"missing automation account and unable to create it: {e}")
            raise e
        finally:
            get_db().remove()

    logging.debug(f"got id {g_int(G_AUTOMATION_USER_ID)} for automation user account")
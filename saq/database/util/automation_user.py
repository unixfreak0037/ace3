import logging
import sys
from saq.constants import G_AUTOMATION_USER_ID
from saq.database.model import User
from saq.database.pool import get_db
from saq.environment import g_int, set_g


def initialize_automation_user():
    # get the id of the ace automation account
    try:
        set_g(G_AUTOMATION_USER_ID, get_db().query(User).filter(User.username == 'ace').one().id)
        get_db().remove()
    except Exception as e:
        # if the account is missing go ahead and create it
        user = User(username='ace', email='ace@localhost', display_name='automation')
        get_db().add(user)
        get_db().commit()

        try:
            set_g(G_AUTOMATION_USER_ID, get_db().query(User).filter(User.username == 'ace').one().id)
        except Exception as e:
            logging.error(f"missing automation account and unable to create it: {e}")
            raise e
        finally:
            get_db().remove()

    logging.debug(f"got id {g_int(G_AUTOMATION_USER_ID)} for automation user account")
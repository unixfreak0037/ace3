from app.application import create_app, login_manager
from app.orm_events import before_cursor_execute, after_cursor_execute
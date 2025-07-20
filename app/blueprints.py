from flask import Blueprint, Flask

analysis = Blueprint("analysis", __name__)
main = Blueprint('main', __name__)
events = Blueprint('events', __name__, url_prefix='/events')
auth = Blueprint('auth', __name__)

def register_blueprints(flask_app: Flask):
    import app.main
    import app.auth
    import app.analysis
    import app.events

    flask_app.register_blueprint(main)
    flask_app.register_blueprint(auth)
    flask_app.register_blueprint(analysis)
    flask_app.register_blueprint(events)
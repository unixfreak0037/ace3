import logging
import os
from flask import make_response, render_template, request
from flask_login import login_required
from app.blueprints import analysis
from saq.database.pool import get_db
from saq.gui.alert import GUIAlert

@analysis.route('/image', methods=['GET'])
@login_required
def image():
    alert_uuid = request.values['alert_uuid']
    observable_uuid = request.values['observable_uuid']

    alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == alert_uuid).one()
    alert.load()
    _file = alert.get_observable(observable_uuid)

    if not os.path.exists(_file.path):
        logging.info(f"attempted to display {_file.path} as image but file does not exist")
        return "unknown file", 404

    with open(_file.path, 'rb') as fp:
        result = fp.read()

    response = make_response(result)
    response.headers['Content-Type'] = _file.mime_type
    return response

@analysis.route('/image_full', methods=['GET'])
@login_required
def image_full():
    alert_uuid = request.values['alert_uuid']
    observable_uuid = request.values['observable_uuid']
    return render_template(
        'analysis/image_full.html',
        alert = alert_uuid,
        observable = observable_uuid,
    )
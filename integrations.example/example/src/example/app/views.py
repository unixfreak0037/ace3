from flask import render_template, request
from example import example_bp
from saq.database.util.alert import get_alert_by_uuid

@example_bp.route('/', methods=['GET', 'POST'])
def index():
    return render_template('example/index.html')

@example_bp.route('/example_observable_action', methods=['GET', 'POST'])
def example_observable_action():
    from flask import jsonify
    observable_uuid = request.form.get('observable_uuid')
    alert_uuid = request.form.get('alert_uuid')
    action_id = request.form.get('action_id')

    alert = get_alert_by_uuid(alert_uuid)

    return jsonify({"observable_uuid": observable_uuid, "alert_uuid": alert_uuid, "action_id": action_id, "alert": alert.description})

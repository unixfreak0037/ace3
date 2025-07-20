from datetime import datetime
import logging
from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import func
from app.analysis.views.session.alert import get_current_alert
from app.blueprints import analysis
from saq.constants import ACTION_ENABLE_DETECTION
from saq.database.model import Observable
from saq.database.pool import get_db
from saq.error.reporting import report_exception

@analysis.route('/observable_action_set_for_detection', methods=['POST'])
@login_required
def observable_action_set_for_detection():
    alert = get_current_alert()
    if alert is None:
        return "Error: unable to find alert", 200
    try:
        alert.load()
    except Exception as e:
        return f"Error: unable to load alert {alert}: {e}", 200

    observable = alert.get_observable(request.form.get('observable_uuid'))
    if not observable:
        return "Error: unable to find observable in alert", 200

    try:
        db_observable = get_db().query(Observable).filter(Observable.type==observable.type, Observable.md5==func.UNHEX(observable.md5_hex)).one()
    except Exception as e:
        error_message = f"Error: unable to update observable for_detection: {e}"
        logging.error(error_message)
        return error_message, 500

    for_detection_status = 'disabled'
    action_id = request.form.get('action_id')
    try:
        if action_id == ACTION_ENABLE_DETECTION:
            for_detection_status = 'enabled'
            db_observable.for_detection = True
            db_observable.enabled_by = current_user.id
            db_observable.detection_context = f"manually enabled in the gui by {current_user} for alert {alert.description} ({alert.uuid})"
        else:
            db_observable.for_detection = False

        logging.info(f"AUDIT: {current_user} {for_detection_status} observable {observable.value} for detection")
        get_db().add(db_observable)
        get_db().commit()

    except Exception as e:
        logging.error(f"Error: unable to update observable for_detection to {for_detection_status}: {e}")
        report_exception()
        return f"Error: Observable for detection status update failed; for_detection remains {not for_detection_status}", 500

    return f"Observable {for_detection_status} for detection", 200

@analysis.route('/observable_action_adjust_expiration', methods=['POST'])
@login_required
def observable_action_adjust_expiration():
    alert_uuid = request.form.get('alert_uuid')
    redirection_params = {'direct': alert_uuid}
    redirection = redirect(url_for('analysis.index', **redirection_params))

    alert = get_current_alert()
    if alert is None:
        return "Error: unable to find alert", 200
    try:
        alert.load()
    except Exception as e:
        flash(f"Error: unable to load alert {alert}: {e}", 'error')
        return redirection

    observable_uuid = request.form.get('observable_uuid')
    observable = alert.get_observable(observable_uuid)
    if not observable:
        flash("Error: unable to find observable in alert", 'error')
        return redirection

    new_expiration_time = None
    if not request.form.get('observable_never_expire'):
        new_expiration_time = request.form.get('observable_expiration_time')
        new_expiration_time = datetime.strptime(new_expiration_time, '%Y-%m-%d %H:%M:%S')

    try:
        observable.expires_on = new_expiration_time
    except Exception as e:
        logging.error(f"Error: unable to update observable expiration date to {new_expiration_time}: {e}")
        report_exception()
        flash(f"Error: Observable expiration date update failed", 'error')
        return redirection

    logging.info("AUDIT: user %s set expiration for %s to %s", current_user, observable, new_expiration_time)
    flash(f"Observable expiration date set to {new_expiration_time}")
    return redirection
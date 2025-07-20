from datetime import datetime
import logging
import os
from uuid import uuid4
from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required
import ace_api
from app.analysis.views.session.alert import get_current_alert
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.database.model import Alert
from saq.database.util.locking import acquire_lock, release_lock
from saq.environment import get_base_dir
from saq.error.reporting import report_exception
from saq.util.filesystem import abs_path

@analysis.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    downloadfile = request.files['file_path']
    comment = request.form.get("comment", "")
    alert_uuid = request.form.get("alert_uuid","")
    if not downloadfile:
        flash("No file specified for upload.")
        return redirect(url_for('analysis.file'))

    file_name = downloadfile.filename
    if not alert_uuid:
        alert = Alert()
        alert.tool = 'Manual File Upload - '+file_name
        alert.tool_instance = get_config()['global']['instance_name']
        alert.alert_type = 'manual_upload'
        alert.description = 'Manual File upload {0}'.format(file_name)
        alert.event_time = datetime.now()
        alert.details = {'user': current_user.username, 'comment': comment}

        # XXX database.Alert does not automatically create this
        alert.uuid = str(uuid4())

        # we use a temporary directory while we process the file
        alert.storage_dir = os.path.join(
            get_config()['global']['data_dir'],
            alert.uuid[0:3],
            alert.uuid)

        dest_path = os.path.join(get_base_dir(), alert.storage_dir)
        if not os.path.isdir(dest_path):
            try:
                os.makedirs(dest_path)
            except Exception as e:
                logging.error("unable to create directory {0}: {1}".format(dest_path, str(e)))
                report_exception()
                return

        # XXX fix this!! we should not need to do this
        # we need to do this here so that the proper subdirectories get created
        alert.save()

        alert.lock_uuid = acquire_lock(alert.uuid)
        if not alert.lock_uuid:
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))
    else:
        alert = get_current_alert()
        alert.lock_uuid = acquire_lock(alert.uuid)
        if not alert.lock_uuid:
            flash("unable to lock alert {}".format(alert))
            return redirect(url_for('analysis.index'))

        if not alert.load():
            flash("unable to load alert {}".format(alert))
            return redirect(url_for('analysis.index'))
            
    dest_path = os.path.join(get_base_dir(), alert.storage_dir, os.path.basename(downloadfile.filename))

    try:
        downloadfile.save(dest_path)
    except Exception as e:
        flash("unable to save {} to {}: {}".format(file_name, dest_path, str(e)))
        report_exception()
        if alert.lock_uuid:
            release_lock(alert.uuid, alert.lock_uuid)

        return redirect(url_for('analysis.file'))

    alert.add_file_observable(dest_path)
    alert.sync()
    alert.schedule()
    
    if alert.lock_uuid:
        release_lock(alert.uuid, alert.lock_uuid)

    return redirect(url_for('analysis.index', direct=alert.uuid))

@analysis.route('/analyze_alert', methods=['POST'])
@login_required
def analyze_alert():
    alert = get_current_alert()

    try:
        result = ace_api.resubmit_alert(
            remote_host = alert.node_location,
            ssl_verification = abs_path(get_config()['SSL']['ca_chain_path']),
            uuid = alert.uuid)

        if 'error' in result:
            e_msg = result['error']
            logging.error(f"failed to resubmit alert: {e_msg}")
            flash(f"failed to resubmit alert: {e_msg}")
        else:
            flash("successfully submitted alert for re-analysis")

    except Exception as e:
        logging.error(f"unable to submit alert: {e}")
        flash(f"unable to submit alert: {e}")

    return redirect(url_for('analysis.index', direct=alert.uuid))
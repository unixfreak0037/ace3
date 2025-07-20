import logging
from flask import flash, redirect, request, session, url_for
from flask_login import current_user, login_required
from app.analysis.views.session.alert import get_current_alert
from app.analysis.views.session.filters import reset_checked_alerts
from app.blueprints import analysis

@analysis.route('/redirect_to', methods=['GET', "POST"])
@login_required
def redirect_to():
    alert = get_current_alert()
    if alert is None:
        flash("internal error")
        return redirect(url_for('analysis.index'))

    if not alert.load():
        flash("internal error")
        logging.error("unable to load alert {0}".format(alert))
        return redirect(url_for('analysis.index'))

    try:
        file_uuid = request.values['file_uuid']
    except KeyError:
        logging.error("missing file_uuid")
        return "missing file_uuid", 500

    try:
        target = request.values['target']
    except KeyError:
        logging.error("missing target")
        return "missing target", 500

    # find the observable with this uuid
    try:
        file_observable = alert.observable_store[file_uuid]
    except KeyError:
        logging.error("missing file observable uuid {0} for alert {1} user {2}".format(
            file_uuid, alert, current_user))
        flash("internal error")
        return redirect(url_for('analysis.index'))

    # both of these requests require the sha256 hash
    # as on 12/23/2015 the FileObservable stores these hashes as a part of the observable
    # so we use that if it exists, otherwise we compute it on-the-fly
    if file_observable.sha256_hash is None:
        if not file_observable.compute_hashes():
            flash("unable to compute file hash of {}".format(file_observable.value))
            return redirect(url_for('analysis.index'))

    flash("invalid target {}".format(target))
    return redirect(url_for('analysis.index'))

@analysis.route('/set_page_offset', methods=['GET', 'POST'])
@login_required
def set_page_offset():
    # reset page options
    reset_checked_alerts()

    # set page offset
    session['page_offset'] = int(request.args['offset']) if request.method == 'GET' else int(request.form['offset'])

    # return empy page
    return ('', 204)

@analysis.route('/set_page_size', methods=['GET', 'POST'])
@login_required
def set_page_size():
    # reset page options
    reset_checked_alerts()

    # set page size
    session['page_size'] = int(request.args['size']) if request.method == 'GET' else int(request.form['size'])

    # return empy page
    return ('', 204)
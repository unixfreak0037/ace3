import bisect
import time
from flask import render_template, request
from flask_login import current_user, login_required
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.database.model import Alert, Observable, ObservableMapping
from saq.database.pool import get_db
from saq.observables.generator import create_observable
from saq.remediation import RemediationTarget

def get_remediation_targets(alert_uuids):
    # get all remediatable observables from the given alert uuids
    query = get_db().query(Observable, Alert)
    query = query.join(ObservableMapping, Observable.id == ObservableMapping.observable_id)
    query = query.join(Alert, ObservableMapping.alert_id == Alert.id)
    query = query.filter(Alert.uuid.in_(alert_uuids))
    observables = query.all()

    # get remediation targets for each observable
    targets = {}
    for o, a in observables:
        observable = create_observable(o.type, o.display_value)
        observable.alert = a
        for target in observable.remediation_targets:
            target.observable_id = o.id
            targets[target.id] = target

    # return sorted list of targets
    targets = list(targets.values())
    targets.sort(key=lambda x: f"{x.observable_id}|{x.type}|{x.value}")

    # 4/7/2021 - de-dupe this list, the type + value should be unique
    temp = {} # key = {x.type}{x.value}, value = target
    for target in targets:
        # map everything to the key, if it already exists just skip it
        key = f"{target.type}|{target.value}".lower()
        if key not in temp:
            temp[key] = target

    targets = list(temp.values())
    return targets

@analysis.route('/remediation_targets', methods=['POST', 'PUT', 'DELETE', 'PATCH'])
@login_required
def remediation_targets():
    # get request body
    body = request.get_json()

    # return rendered target selection table
    if request.method == 'POST':
        unchecked_types = [_.strip() for _ in get_config()['service_remediation']['unchecked_types'].split(',')]
        targets = get_remediation_targets(body['alert_uuids'])
        targets_by_type = {}
        for target in targets:
            if target.type in targets_by_type:
                bisect.insort(targets_by_type[target.type], target)
            else:
                targets_by_type[target.type] = [target]

        return render_template('analysis/remediation_targets.html', targets=targets, unchecked_types=unchecked_types,
                               targets_by_type=targets_by_type,
                               target_types=sorted([*targets_by_type]))

    if request.method == 'PATCH':
        for target in body['targets']:
            if body['action'] == 'stop':
                RemediationTarget(id=target).stop_remediation()
                return 'remediation stopped', 200
            elif body['action'] == 'delete':
                RemediationTarget(id=target).delete_remediation()
                return 'remediation deleted', 200

    # queue targets for removal/restoration
    action = 'remove' if request.method == 'DELETE' else 'restore'
    for target in body['targets']:
        RemediationTarget(id=target).queue(action, current_user.id)

    # wait until all remediations are complete or we run out of time
    complete = False
    quit_time = time.time() + get_config()['service_remediation'].getint('request_wait_time', fallback=10)
    while not complete and time.time() < quit_time:
        complete = True
        for target in body['targets']:
            if RemediationTarget(id=target).processing:
                complete = False
                break
        time.sleep(1)

    # return rendered remediation results table
    targets=[RemediationTarget(id=target) for target in body['targets']]
    sorted_targets = {}
    for t in targets:
        if t.type not in sorted_targets:
            sorted_targets[t.type] = []
        sorted_targets[t.type].append(t)
    return render_template('analysis/remediation_results.html', target_types=sorted_targets)
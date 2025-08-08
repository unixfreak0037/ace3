function remediation_targets(method, body, modal_id) {
    (function() {
        fetch('remediation_targets', {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            credentials: 'same-origin'
        })
        .then(function(resp){
            if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            return resp.text();
        })
        .then(function(html){
            $(modal_id).html(html);
        })
        .catch(function(err){
            $(modal_id).modal('hide');
            alert('Failed to ' + method + ' remediation targets: ' + err.message);
        });
    })();
}

function get_remediation_targets() {
    var targets = Array();
    $("input[name$='remediation_target']").each(function(index) {
        if ($(this).is(":checked")) {
            targets.push($(this).prop("id"))
        }
    });
    return targets;
}

function show_remediation_targets(alert_uuids) {
    $('#remediation-selection-body').html('loading data...');
    $('#remediation-selection-modal').modal('show');
    remediation_targets("POST", {alert_uuids: alert_uuids}, '#remediation-selection-body');
}

function restore_remediation_targets() {
    $('#remediation-selection-modal').modal('hide');
    $('#remediation-body').html('restoring targets...');
    $('#remediation-modal').modal('show');
    targets = get_remediation_targets()
    remediation_targets("PUT", {targets: targets}, '#remediation-body');
    return false; // prevents form from submitting
}

function remove_remediation_targets() {
    $('#remediation-selection-modal').modal('hide');
    $('#remediation-body').html('removing targets...');
    $('#remediation-modal').modal('show');
    targets = get_remediation_targets()
    remediation_targets("DELETE", {targets: targets}, '#remediation-body');
    return false; // prevents form from submitting
}

function stop_remediation() {
    $('#remediation-body').html('stopping remediation...');
    $('#remediation-selection-modal').modal('hide');
    $('#remediation-modal').modal('show');
    targets = get_remediation_targets();
    remediation_targets("PATCH", {targets: targets, 'action': 'stop'}, '#remediation-body');
}

function delete_remediation() {
    $('#remediation-body').html('deleting remediation...');
    $('#remediation-selection-modal').modal('hide');
    $('#remediation-modal').modal('show');
    targets = get_remediation_targets();
    remediation_targets("PATCH", {targets: targets, 'action': 'delete'}, '#remediation-body');
}

function update_checkbox_count(target_type) {
   let targets = $(`input[name="${target_type}_remediation_target"]`).length;
   let checked_targets = $(`input[name="${target_type}_remediation_target"]:checked`).length;
   let checked_counter = $(`#${target_type}_checked_counter`);
   checked_counter.text(`${checked_targets}/${targets}`);
}

function remediation_targets(method, body, modal_id) {
    $.ajax({
        type: method,
        url: 'remediation_targets',
        dataType: "html",
        contentType: "application/json",
        data: JSON.stringify(body),
        processData: false,
        success: function(data, textStatus, jqXHR) {
            $(modal_id).html(data);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            $(modal_id).modal('hide');
            alert("Failed to " + method + " remediation targets: " + errorThrown);
        }
    });
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

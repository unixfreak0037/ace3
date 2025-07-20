function setup_daterange_pickers() {
    $('.daterange').each(function(index) {
        if ($(this).val() == '') {
            $(this).val(
                moment().subtract(59, "days").startOf('day').format("MM-DD-YYYY HH:mm") + ' - ' +
                moment().format("MM-DD-YYYY HH:mm"));
        }
    });

    $('.daterange').daterangepicker({
        timePicker: true,
        format: 'MM-DD-YYYY HH:mm',
        startDate:  moment().subtract(59, 'days').startOf('day'),
        endDate: moment(),
        ranges: {
           'Last 24 Hours': [moment().subtract(24, 'hours'), moment()],
           'Last 7 Days': [moment().subtract(6, 'days').startOf('day'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days').startOf('day'), moment()],
           'Last 60 Days': [moment().subtract(59, 'days').startOf('day'), moment()],
        }
    });
}

function setup_timezone() {
    $('#timezone').val(Intl.DateTimeFormat().resolvedOptions().timeZone)
}

$(document).ready(function() {
    setup_daterange_pickers();
    setup_timezone();
});

from datetime import datetime, timedelta
import json
import logging
from subprocess import PIPE, Popen
import traceback
from flask import flash, render_template, request
from flask_login import login_required
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.constants import G_DEFAULT_ENCODING, VALID_OBSERVABLE_TYPES
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.environment import g
from saq.gui.alert import GUIAlert

@analysis.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'GET':
        return render_template('analysis/search.html', observable_types=VALID_OBSERVABLE_TYPES)

    query = request.form.get('search', None)
    if query is None:
        flash("missing search field")
        return render_template('analysis/search.html', observable_types=VALID_OBSERVABLE_TYPES)

    search_comments = request.form.get('search_comments', False)
    search_details = request.form.get('search_details', False)
    search_all = request.form.get('search_all', False)
    search_daterange = request.form.get('daterange', '')

    uuids = []
    cache_lookup = False

    # does the search start with "indicator_type:"?
    for o_type in VALID_OBSERVABLE_TYPES:
        if query.lower().startswith('{0}:'.format(o_type.lower())):
            # search the cache
            cache_lookup = True
            try:
                with open(get_config().get('global', 'cache'), 'r') as fp:
                    try:
                        cache = json.load(fp)
                    except Exception as e:
                        flash("failed to load cache: {0}".format(str(e)))
                        raise e

                (o_type, o_value) = query.split(':', 2)
                if o_type in cache:
                    if o_value in cache[o_type]:
                        logging.debug("found cached alert uuids for type {0} value {1}".format(o_type, o_value))
                        uuids.extend(cache[o_type][o_value])  # XXX case issues here

            except Exception as e:
                flash(str(e))
                return render_template('analysis/search.html')

    if not cache_lookup:
        # generate a list of files to look through
        # we use the date range to query the database for alerts that were generated during that time
        try:
            daterange_start, daterange_end = search_daterange.split(' - ')
            daterange_start = datetime.strptime(daterange_start, '%m-%d-%Y %H:%M')
            daterange_end = datetime.strptime(daterange_end, '%m-%d-%Y %H:%M')
        except Exception as error:
            flash("error parsing date range, using default 7 days: {0}".format(str(error)))
            daterange_end = datetime.now()
            daterange_start = daterange_end - timedelta(days=7)

        for alert in get_db().query(GUIAlert).filter(GUIAlert.insert_date.between(daterange_start, daterange_end)):
            args = [
                'find', '-L',
                alert.storage_dir,
                # get_config().get('global', 'data_dir'),
                '-name', 'data.json']

            if search_details:
                args.extend(['-o', '-name', '*.json'])

            if search_all:
                args.extend(['-o', '-type', 'f'])

            logging.debug("executing {0}".format(' '.join(args)))

            p = Popen(args, stdout=PIPE)
            for file_path in p.stdout:
                file_path = file_path.decode(g(G_DEFAULT_ENCODING)).strip()
                grep = Popen(['grep', '-l', query, file_path], stdout=PIPE)
                logging.debug("searching {0} for {1}".format(file_path, query))
                for result in grep.stdout:
                    result = result.decode(g(G_DEFAULT_ENCODING)).strip()
                    logging.debug("result in {0} for {1}".format(result, query))
                    result = result[len(get_config().get('global', 'data_dir')) + 1:]
                    result = result.split('/')
                    result = result[1]
                    uuids.append(result)

    if search_comments:
        for disposition in get_db().query(Alert).filter(Alert.comment.like('%{0}%'.format(query))):
            uuids.append(disposition.alert.uuid)

    alerts = []
    for uuid in list(set(uuids)):
        try:
            alert = get_db().query(GUIAlert).filter(GUIAlert.uuid == uuid).one()
            alert.load()
            alerts.append(alert)
        except Exception as e:
            logging.error("unable to load alert uuid {0}: {1}".format(uuid, str(e)))
            traceback.print_exc()
            continue

    return render_template('analysis/search.html',
                           query=query,
                           results=alerts,
                           search_comments_checked='CHECKED' if search_comments else '',
                           search_details_checked='CHECKED' if search_details else '',
                           search_all_checked='CHECKED' if search_all else '',
                           search_daterange=search_daterange)
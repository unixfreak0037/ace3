from flask import render_template, session
from flask_login import current_user, login_required
import pytz
from sqlalchemy import distinct, func
from app.analysis.views.session.filters import _reset_filters, create_filter, getFilters, hasFilter, reset_checked_alerts, reset_pagination, reset_sort_filter
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.constants import CLOSED_EVENT_LIMIT, G_SAQ_NODE
from saq.database.model import Campaign, DispositionBy, Observable, ObservableMapping, ObservableRemediationMapping, Owner, RemediatedBy, Remediation, Tag, TagMapping, Comment, Event, User
from saq.database.pool import get_db
from saq.disposition import get_dispositions
from saq.environment import g
from saq.gui.alert import GUIAlert
from sqlalchemy.orm import selectinload

@analysis.route('/manage', methods=['GET', 'POST'])
@login_required
def manage():
    # use default page settings if first visit
    if 'filters' not in session:
        _reset_filters()
    if 'checked' not in session:
        reset_checked_alerts()
    if 'page_offset' not in session or 'page_size' not in session:
        reset_pagination()
    if 'sort_filter' not in session or 'sort_filter_desc' not in session:
        reset_sort_filter()

    # create alert view by joining required tables
    query = get_db().query(GUIAlert).with_labels()
    query = query.outerjoin(Owner, GUIAlert.owner_id == Owner.id)
    if hasFilter('Disposition By'):
        query = query.outerjoin(DispositionBy, GUIAlert.disposition_user_id == DispositionBy.id)
    if hasFilter('Remediated By'):
        query = query.outerjoin(RemediatedBy, GUIAlert.removal_user_id == RemediatedBy.id)

    if hasFilter('Observable') or hasFilter('Remediation Status'):
        query = query.outerjoin(ObservableMapping)\
            .outerjoin(Observable)\
            .outerjoin(ObservableRemediationMapping)\
            .outerjoin(Remediation)\

    if hasFilter('Tag'):
        query= query.outerjoin(TagMapping, GUIAlert.id == TagMapping.alert_id).join(Tag, TagMapping.tag_id == Tag.id)

    #query = query.options(selectinload('workload'))
    query = query.options(selectinload(GUIAlert.workload))
    #query = query.options(selectinload('delayed_analysis'))
    query = query.options(selectinload(GUIAlert.delayed_analysis))
    #query = query.options(selectinload('lock'))
    query = query.options(selectinload(GUIAlert.lock))
    #query = query.options(selectinload('observable_mappings'))
    query = query.options(selectinload(GUIAlert.observable_mappings))
    #query = query.options(selectinload('observable_mappings.observable'))
    #query = query.options(selectinload(GUIAlert.observable_mappings.observable))
    #query = query.options(selectinload('observable_mappings.observable.observable_remediation_mappings'))
    #query = query.options(selectinload(GUIAlert.observable_mappings.observable.observable_remediation_mappings))
    #query = query.options(selectinload('observable_mappings.observable.observable_remediation_mappings.remediation'))
    #query = query.options(selectinload(GUIAlert.observable_mappings.observable.observable_remediation_mappings.remediation))
    #query = query.options(selectinload('event_mapping'))
    query = query.options(selectinload(GUIAlert.event_mapping))
    #query = query.options(selectinload('tag_mapping'))
    query = query.options(selectinload(GUIAlert.tag_mapping))

    # apply filters
    for filter_dict in session["filters"]:
        _filter = create_filter(filter_dict["name"], inverted=filter_dict["inverted"])
        query = _filter.apply(query, filter_dict["values"])

    # only show alerts from this node
    # NOTE: this will not be necessary once alerts are stored externally
    if get_config()['gui'].getboolean('local_node_only', fallback=True):
        query = query.filter(GUIAlert.location == g(G_SAQ_NODE))
    elif get_config()['gui'].get('display_node_list', fallback=None):
        # alternatively we can display alerts for specific nodes
        # this was added on 05/02/2023 to support a DR mode of operation
        display_node_list = [_.strip() for _ in get_config()['gui'].get('display_node_list').split(',') if _.strip()]
        query = query.filter(GUIAlert.location.in_(display_node_list))

    # get total number of alerts
    count_query = query.statement.with_only_columns(func.count(distinct(GUIAlert.id)))
    total_alerts = get_db().execute(count_query).scalar()

    # group by id to prevent duplicates
    query = query.group_by(GUIAlert.id)

    # apply sort filter
    sort_filters = {
        'Alert Date': GUIAlert.insert_date,
        'Description': GUIAlert.description,
        'Disposition': GUIAlert.disposition,
        'Owner': Owner.display_name,
    }
    if session['sort_filter_desc']:
        query = query.order_by(sort_filters[session['sort_filter']].desc(), GUIAlert.id.desc())
    else:
        query = query.order_by(sort_filters[session['sort_filter']].asc(), GUIAlert.id.asc())

    # apply pagination
    query = query.limit(session['page_size'])
    if session['page_offset'] >= total_alerts:
        session['page_offset'] = (total_alerts // session['page_size']) * session['page_size']
    if session['page_offset'] < 0:
        session['page_offset'] = 0
    query = query.offset(session['page_offset'])

    # execute query to get all alerts
    alerts = query.all()

    # load alert comments
    # NOTE: We should have the alert class do this automatically
    comments = {}
    if alerts:
        for comment in get_db().query(Comment).filter(Comment.uuid.in_([a.uuid for a in alerts])):
            if comment.uuid not in comments:
                comments[comment.uuid] = []
            comments[comment.uuid].append(comment)

    # load alert tags
    # NOTE: We should have the alert class do this automatically
    alert_tags = {}
    if alerts:
        tag_query = get_db().query(Tag, GUIAlert.uuid).join(TagMapping, Tag.id == TagMapping.tag_id).join(GUIAlert, GUIAlert.id == TagMapping.alert_id)
        tag_query = tag_query.filter(GUIAlert.id.in_([a.id for a in alerts]))
        ignore_tags = [tag for tag in get_config()['tags'].keys() if get_config()['tags'][tag] in ['special', 'hidden' ]]
        tag_query = tag_query.filter(Tag.name.notin_(ignore_tags))
        tag_query = tag_query.order_by(Tag.name.asc())
        for tag, alert_uuid in tag_query:
            if alert_uuid not in alert_tags:
                alert_tags[alert_uuid] = []
            alert_tags[alert_uuid].append(tag)

    # alert display timezone
    if current_user.timezone and pytz.timezone(current_user.timezone) != pytz.utc:
        for alert in alerts:
            alert.display_timezone = pytz.timezone(current_user.timezone)

    open_events = []
    event_query_results = get_db().query(Event).filter(Event.status.has(value='OPEN')).order_by(Event.creation_date.desc()).all()
    if event_query_results:
        open_events = event_query_results

    internal_collection_events = []
    event_query_results = get_db().query(Event).filter(Event.status.has(value='INTERNAL COLLECTION')).order_by(Event.creation_date.desc())\
        .all()
    if event_query_results:
        internal_collection_events = event_query_results

    closed_events = []
    end_of_closed_events_list = True
    event_query_results = get_db().query(Event).filter(Event.status.has(value='CLOSED')).order_by(Event.creation_date.desc())\
        .limit(CLOSED_EVENT_LIMIT).all()
    if event_query_results:
        if len(event_query_results) == CLOSED_EVENT_LIMIT:
            end_of_closed_events_list = False
        closed_events = event_query_results

    return render_template(
        'analysis/manage.html',
        # settings
        ace_config=get_config(),
        session=session,
        dispositions=get_dispositions(),

        # filter
        filters=getFilters(),
        
        # alert data
        alerts=alerts,
        comments=comments,
        alert_tags=alert_tags,
        display_disposition=not ('Disposition' in session['filters'] and len(session['filters']['Disposition']) == 1 and session['filters']['Disposition'][0] is None),
        total_alerts=total_alerts,

        # event data
        open_events=open_events,
        internal_collection_events=internal_collection_events,
        closed_events=closed_events,
        end_of_list=end_of_closed_events_list,
        campaigns=get_db().query(Campaign).order_by(Campaign.name.asc()).all(),

        # user data
        all_users=get_db().query(User).all(),
    )
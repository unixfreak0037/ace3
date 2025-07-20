import pytest
from sqlalchemy import LABEL_STYLE_TABLENAME_PLUS_COL

from saq.database import Owner, get_db
from saq.gui import GUIAlert

from sqlalchemy.orm import selectinload

@pytest.mark.integration
def test_manage():
    # create alert view by joining required tables
    query = get_db().query(GUIAlert).set_label_style(LABEL_STYLE_TABLENAME_PLUS_COL)
    query = query.outerjoin(Owner, GUIAlert.owner_id == Owner.id)

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
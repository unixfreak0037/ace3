# vim: sw=4:ts=4:et

from flask_wtf import FlaskForm
from wtforms import SubmitField

class AppModeSelectionForm(FlaskForm):
    manage_alerts = SubmitField('Manage Alerts')
    analyze_alerts = SubmitField('Analyze Alerts')
    metrics = SubmitField('Metrics')

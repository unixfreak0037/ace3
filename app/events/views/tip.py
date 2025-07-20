from flask_login import login_required
from app.blueprints import events

@events.route('/add_indicators_to_event_in_tip', methods=['POST'])
@login_required
def add_indicators_to_event_in_tip():
    # Add the indicators to the TIP in the background
    pass
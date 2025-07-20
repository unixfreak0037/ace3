from saq.constants import ACTION_ADD_LOCAL_EMAIL_DOMAIN, ACTION_ADD_TAG, ACTION_ADJUST_EXPIRATION
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionAddLocalEmailDomain(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_ADD_LOCAL_EMAIL_DOMAIN
        self.description = "Add Local Email Domain"
        self.jinja_action_path = 'analysis/observable_actions/add_local_email_domain.html'
        self.icon = 'plus'

class ObservableActionAddTag(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_ADD_TAG
        self.description = "Add Tag"
        self.jinja_action_path = 'analysis/observable_actions/input_tag.html'
        self.icon = 'plus'

class ObservableActionAdjustExpiration(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_ADJUST_EXPIRATION
        self.description = "Adjust expiration datetime for observable"
        self.jinja_action_path = 'analysis/observable_actions/adjust_expiration.html'
        self.icon = 'time'
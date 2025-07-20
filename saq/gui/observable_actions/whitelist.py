from saq.constants import ACTION_UN_WHITELIST, ACTION_WHITELIST
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionWhitelist(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_WHITELIST
        self.description = "Whitelist"
        self.jinja_action_path = 'analysis/observable_actions/whitelist.html'
        self.icon = 'ok'

class ObservableActionUnWhitelist(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_UN_WHITELIST
        self.description = "Un-Whitelist"
        self.jinja_action_path = 'analysis/observable_actions/un_whitelist.html'
        self.icon = 'remove'
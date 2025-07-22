from saq.constants import ACTION_DISABLE_DETECTION, ACTION_ENABLE_DETECTION
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionEnableDetection(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_ENABLE_DETECTION
        self.description = "Enable observable for future detection"
        self.action_path = 'analysis/observable_actions/enable_detection.html'
        self.icon = 'ok'

class ObservableActionDisableableDetection(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_DISABLE_DETECTION
        self.description = "Disable observable for future detection"
        self.action_path = 'analysis/observable_actions/disable_detection.html'
        self.icon = 'remove'
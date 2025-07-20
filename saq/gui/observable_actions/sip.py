from saq.constants import ACTION_SET_SIP_INDICATOR_STATUS_ANALYZED, ACTION_SET_SIP_INDICATOR_STATUS_INFORMATIONAL, ACTION_SET_SIP_INDICATOR_STATUS_NEW
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionSetSIPIndicatorStatus_Analyzed(ObservableAction):
    """Action to set the status of a SIP indicator to Analyzed."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_SET_SIP_INDICATOR_STATUS_ANALYZED
        self.description = "Set SIP indicator status to Analyzed"
        self.jinja_action_path = 'analysis/observable_actions/set_sip_indicator_status.html'
        self.icon = 'thumbs-up'

class ObservableActionSetSIPIndicatorStatus_Informational(ObservableAction):
    """Action to set the status of a SIP indicator to Informational."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_SET_SIP_INDICATOR_STATUS_INFORMATIONAL
        self.description = "Set SIP indicator status to Informational"
        self.jinja_action_path = 'analysis/observable_actions/set_sip_indicator_status.html'
        self.icon = 'remove'

class ObservableActionSetSIPIndicatorStatus_New(ObservableAction):
    """Action to set the status of a SIP indicator to New."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_SET_SIP_INDICATOR_STATUS_NEW
        self.description = "Set SIP indicator status to New"
        self.jinja_action_path = 'analysis/observable_actions/set_sip_indicator_status.html'
        self.icon = 'refresh'
from saq.constants import ACTION_FILE_UPLOAD_VT, ACTION_FILE_VIEW_VT
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionUploadToVt(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_UPLOAD_VT
        self.description = "Upload To VirusTotal"
        self.jinja_action_path = 'analysis/observable_actions/upload_to_vt.html'
        self.icon = 'export'

class ObservableActionViewInVt(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = ACTION_FILE_VIEW_VT
        self.description = "View In VirusTotal"
        self.jinja_action_path = 'analysis/observable_actions/view_in_vt.html'
        self.icon = 'chevron-right'
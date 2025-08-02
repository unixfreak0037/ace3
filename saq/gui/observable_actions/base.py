class ObservableAction:
    """Represents an "action" that a user can take with an Observable in the GUI."""
    def __init__(self):
        self.name = None
        self.description = None
        self.action_path = None
        self.icon = None
        self.display = True

class ObservableActionSeparator(ObservableAction):
    """Use this to place separator bars in your list of action choices."""
    pass
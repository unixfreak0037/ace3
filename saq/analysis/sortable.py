KEY_SORT_ORDER = 'sort_order'


class SortManager:
    """Manages sort-related functionality for any object through composition."""

    def __init__(self, sort_order=100):
        self.sort_order = sort_order

    def get_json_data(self):
        """Returns sort data for JSON serialization."""
        return {KEY_SORT_ORDER: self.sort_order}

    def set_json_data(self, value):
        """Sets sort data from JSON deserialization."""
        if KEY_SORT_ORDER in value:
            self.sort_order = value[KEY_SORT_ORDER]

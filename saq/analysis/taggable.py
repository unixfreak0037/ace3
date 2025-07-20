import logging
from saq.analysis.event_source import EventSource
from saq.analysis.tag import Tag
from saq.constants import DIRECTIVE_WHITELISTED, EVENT_TAG_ADDED

KEY_TAGS = 'tags'

class TagManager:
    """Manages tag-related functionality for any object through composition."""

    def __init__(self, event_source=None):
        self._tags = []
        self._event_source = event_source

    @property
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, value):
        assert isinstance(value, list)
        assert all([isinstance(i, str) or isinstance(i, Tag) for i in value])
        self._tags = value

    def add_tag(self, tag):
        assert isinstance(tag, str)
        if tag in [t.name for t in self.tags]:
            return

        t = Tag(name=tag)
        self.tags.append(t)
        logging.debug("added {} to {}".format(t, self._event_source or self))
        
        # Fire event if we have an event source
        if self._event_source and hasattr(self._event_source, 'fire_event'):
            self._event_source.fire_event(self._event_source, EVENT_TAG_ADDED, t)

    def remove_tag(self, tag):
        assert isinstance(tag, str)
        self.tags = [t for t in self.tags if t.name != tag]

    def clear_tags(self):
        self._tags = []

    def has_tag(self, tag_value):
        """Returns True if this object has this tag."""
        return tag_value in [x.name for x in self.tags]

    def get_json_data(self):
        """Returns tag data for JSON serialization."""
        return {KEY_TAGS: self.tags}

    def set_json_data(self, value):
        """Sets tag data from JSON deserialization."""
        if KEY_TAGS in value:
            self.tags = value[KEY_TAGS]


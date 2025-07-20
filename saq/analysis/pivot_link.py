class PivotLink:
    URL = "url"
    ICON = "icon"
    TEXT = "text"

    def __init__(self, url, icon, text):
        self.url = url
        self.icon = icon
        self.text = text

    def to_dict(self):
        return {
            PivotLink.URL: self.url,
            PivotLink.ICON: self.icon,
            PivotLink.TEXT: self.text,
        }

    @staticmethod
    def from_dict(d):
        return PivotLink(d.get(PivotLink.URL), d.get(PivotLink.ICON), d.get(PivotLink.TEXT))

    @property
    def json(self):
        return self.to_dict()

    def __eq__(self, other):
        if not isinstance(other, PivotLink):
            return False

        return self.url == other.url and self.icon == other.icon and self.text == other.text

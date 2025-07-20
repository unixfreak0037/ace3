import unicodedata
from saq.analysis.observable import Observable


class ObservableValueError(ValueError):
    pass

class DefaultObservable(Observable):
    """If an observable type does not match a known type then this class is used to represent it."""
    pass

class CaselessObservable(Observable):
    """An observable that doesn't care about the case of the value."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    # see https://stackoverflow.com/a/29247821
    def normalize_caseless(self, value):
        if value is None:
            return None

        return unicodedata.normalize("NFKD", value.casefold())

    def _compare_value(self, other):
        return self.normalize_caseless(self.value) == self.normalize_caseless(other)
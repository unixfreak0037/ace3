
import collections

from saq.constants import DISPOSITION_UNKNOWN


class DispositionHistory(collections.abc.MutableMapping):
    def __init__(self, observable):
        self.observable = observable
        self.history = {} # key = disposition, value = count

    def __getitem__(self, key):
        return self.history[key]

    def __setitem__(self, key, value):
        if key == DISPOSITION_UNKNOWN:
            return
        self.history[key] = value

    def __delitem__(self, key):
        pass

    def __iter__(self):
        total = sum([self.history[disp] for disp in self.history.keys()])
        dispositions = [disposition for disposition in self.history]
        dispositions = sorted(dispositions, key=lambda disposition: (self.history[disposition] / total) * 100.0, reverse=True)
        for disposition in dispositions:
            yield disposition, self.history[disposition], (self.history[disposition] / total) * 100.0

    def __len__(self):
        return len(self.history)
import base64
import pickle
from saq.analysis.observable import Observable
from saq.constants import F_TEST
from saq.observables.generator import map_observable_type


class TestObservable(Observable):
    __test__ = False # tell pytest this is not a test class
    def __init__(self, *args, **kwargs): 
        super().__init__(F_TEST, *args, **kwargs)

    # this allows us to use any object we want for the observable value
    # useful for passing around parameters for testing
    @property
    def value(self):
        return pickle.loads(base64.b64decode(self._value)) # TODO get rid of pickle

    @value.setter
    def value(self, v):
        self._value = base64.b64encode(pickle.dumps(v))

map_observable_type(F_TEST, TestObservable)
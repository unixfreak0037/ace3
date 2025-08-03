from saq.analysis.observable import Observable
from saq.constants import F_TEST
from saq.observables.generator import register_observable_type


class TestObservable(Observable):
    __test__ = False # tell pytest this is not a test class
    def __init__(self, *args, **kwargs): 
        super().__init__(F_TEST, *args, **kwargs)

register_observable_type(F_TEST, TestObservable)
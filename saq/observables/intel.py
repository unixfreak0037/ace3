from saq.analysis.observable import Observable
from saq.constants import F_INDICATOR
from saq.observables.generator import map_observable_type


class IndicatorObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_INDICATOR, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_template_path(self):
        return "analysis/indicator_observable.html"

    @property
    def jinja_available_actions(self):
        result = []
        return result

map_observable_type(F_INDICATOR, IndicatorObservable)
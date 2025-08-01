from saq.constants import F_USER
from saq.observables.base import CaselessObservable
from saq.observables.generator import map_observable_type


class UserObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_USER, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        # Drop the domain/host portion of the username if it's there
        if '\\' in self._value:
            self._value = self._value.split('\\')[1]

    @property
    def jinja_template_path(self):
        return "analysis/user_observable.html"

    @property
    def jinja_available_actions(self):
        result = []
        result.extend(super().jinja_available_actions)
        return result

map_observable_type(F_USER, UserObservable)
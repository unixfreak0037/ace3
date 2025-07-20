from saq.constants import F_ASSET, F_HOSTNAME
from saq.observables.base import CaselessObservable
from saq.observables.generator import map_observable_type


class HostnameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_HOSTNAME, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_template_path(self):
        return "analysis/hostname_observable.html"

class AssetObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_ASSET, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

map_observable_type(F_HOSTNAME, HostnameObservable)
map_observable_type(F_ASSET, AssetObservable)
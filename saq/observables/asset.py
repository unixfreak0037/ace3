from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.constants import F_ASSET, F_HOSTNAME
from saq.observables.base import CaselessObservable
from saq.observables.generator import register_observable_type


class HostnameObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_HOSTNAME, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_template_path(self):
        return "analysis/hostname_observable.html"

class HostnameObservablePresenter(ObservablePresenter):
    """Presenter for HostnameObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/hostname_observable.html"

register_observable_presenter(HostnameObservable, HostnameObservablePresenter)
register_observable_type(F_HOSTNAME, HostnameObservable)

class AssetObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_ASSET, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

register_observable_type(F_ASSET, AssetObservable)
from saq.analysis.observable import Observable
from saq.constants import F_MUTEX, F_WINDOWS_REGISTRY, F_WINDOWS_SERVICE
from saq.observables.generator import register_observable_type


class MutexObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MUTEX, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

class WindowsRegistryObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_WINDOWS_REGISTRY, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()


class WindowsServiceObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_WINDOWS_SERVICE, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

register_observable_type(F_MUTEX, MutexObservable)
register_observable_type(F_WINDOWS_REGISTRY, WindowsRegistryObservable)
register_observable_type(F_WINDOWS_SERVICE, WindowsServiceObservable)
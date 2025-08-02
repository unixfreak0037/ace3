import re

from saq.analysis.observable import Observable
from saq.constants import F_MAC_ADDRESS
from saq.observables.base import ObservableValueError
from saq.observables.generator import register_observable_type


RE_MAC = re.compile(r'^([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?([a-fA-F0-9]{2})[^a-fA-F0-9]*?$')
class MacAddressObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_MAC_ADDRESS, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value

        # try to deal with the various formats of mac addresses
        # some separate with different characters and some don't separate at all
        m = RE_MAC.match(new_value)
        if m is None:
            raise ObservableValueError(f"{new_value} does not parse as a mac address")

        self.mac_parts = m.groups()

    def mac_address(self, sep=':'):
        """Return the mac address formatted with the given separator. Defaults to :"""
        return sep.join(self.mac_parts)

register_observable_type(F_MAC_ADDRESS, MacAddressObservable)
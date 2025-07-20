import validators
from saq.configuration.config import get_config_value_as_list
from saq.constants import CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_DOMAINS, CONFIG_GLOBAL_LOCAL_EMAIL_DOMAINS, F_FQDN
from saq.observables.base import CaselessObservable, ObservableValueError
from saq.observables.generator import map_observable_type
from saq.remediation import RemediationTarget
from saq.util import is_subdomain


class FQDNObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_FQDN, *args, **kwargs)

    @property
    def jinja_template_path(self):
        return "analysis/fqdn_observable.html"

    @CaselessObservable.value.setter
    def value(self, new_value):
        # For whatever reason, the validators library returns an exception instead of raising it.
        if not bool(validators.domain(new_value)):
            raise ObservableValueError(f"{new_value} is not a valid fqdn")

        self._value = new_value.strip()

    @property
    def jinja_available_actions(self):
        result = []
        if not self.is_managed():
            result = [ ]
            result.extend(super().jinja_available_actions)

        return result

    @property
    def remediation_targets(self):
        if self.is_managed():
            return []
        return [RemediationTarget('zerofox_threat', self.value)]

    def is_managed(self):
        """Returns True if this FQDN is a managed DN."""
        for fqdn in get_config_value_as_list(CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_DOMAINS):
            if is_subdomain(self.value, fqdn):
                return True

        for fqdn in get_config_value_as_list(CONFIG_GLOBAL, CONFIG_GLOBAL_LOCAL_EMAIL_DOMAINS):
            if is_subdomain(self.value, fqdn):
                return True

        return False

map_observable_type(F_FQDN, FQDNObservable)
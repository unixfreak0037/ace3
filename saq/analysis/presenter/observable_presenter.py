from typing import TYPE_CHECKING, Type

from saq.database.database_observable import observable_is_set_for_detection

if TYPE_CHECKING:
    from saq.gui import ObservableAction

# Registry for custom observable presenter classes
_OBSERVABLE_PRESENTER_REGISTRY: dict[str, Type["ObservablePresenter"]] = {}


def register_observable_presenter(
    observable_class_name: str, presenter_class: Type["ObservablePresenter"]
):
    """Register a custom presenter for a specific observable class."""
    _OBSERVABLE_PRESENTER_REGISTRY[observable_class_name] = presenter_class


def create_observable_presenter(observable):
    """Factory function to create an appropriate presenter for an Observable object."""
    observable_class_name = type(observable).__name__
    presenter_class = _OBSERVABLE_PRESENTER_REGISTRY.get(
        observable_class_name, ObservablePresenter
    )
    return presenter_class(observable)


# registry for custom observable actions
_OBSERVABLE_ACTION_REGISTRY: dict[str, type["ObservableAction"]] = {}


def register_observable_action(
    observable_type: str, action_class: Type["ObservableAction"]
):
    """Register a custom action for a specific observable type."""
    assert isinstance(observable_type, str)
    assert issubclass(action_class, ObservableAction)
    _OBSERVABLE_ACTION_REGISTRY[observable_type] = action_class


class ObservablePresenter:
    """Handles presentation logic for Observable objects, separating UI concerns from domain logic."""

    def __init__(self, observable):
        """Initialize presenter with an Observable instance."""
        from saq.analysis.observable import Observable

        assert isinstance(observable, Observable)
        self._observable = observable

    @property
    def template_path(self) -> str:
        """Returns the template path to use when rendering this observable."""
        return "analysis/default_observable.html"

    @property
    def available_actions(self) -> list:
        """Returns a list of ObservableAction objects for this observable."""
        from saq.gui import (
            ObservableActionUnWhitelist,
            ObservableActionWhitelist,
            ObservableActionAddTag,
            ObservableActionSeparator,
            ObservableActionEnableDetection,
            ObservableActionDisableableDetection,
            ObservableActionAdjustExpiration,
        )
        from saq.constants import G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES
        from saq.environment import g

        if self._observable.type in g(G_GUI_WHITELIST_EXCLUDED_OBSERVABLE_TYPES):
            actions = [ObservableActionAddTag()]
        else:
            actions = [
                ObservableActionAddTag(),
                ObservableActionSeparator(),
                ObservableActionWhitelist(),
                ObservableActionUnWhitelist(),
            ]

        if observable_is_set_for_detection(self._observable):
            actions.extend(
                [
                    ObservableActionSeparator(),
                    ObservableActionDisableableDetection(),
                    ObservableActionAdjustExpiration(),
                ]
            )
        else:
            actions.extend(
                [ObservableActionSeparator(), ObservableActionEnableDetection()]
            )

        # add any custom actions for this observable type
        if self._observable.type in _OBSERVABLE_ACTION_REGISTRY:
            actions.append(ObservableActionSeparator())
            actions.extend(_OBSERVABLE_ACTION_REGISTRY[self._observable.type]())

        return actions

    # Delegate access to the underlying observable object for any other properties needed
    def __getattr__(self, name):
        """Delegate any missing attributes to the underlying observable object."""
        return getattr(self._observable, name)


# Specialized presenters for specific observable types


class HostnameObservablePresenter(ObservablePresenter):
    """Presenter for HostnameObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/hostname_observable.html"


class EmailAddressObservablePresenter(ObservablePresenter):
    """Presenter for EmailAddressObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/default_observable.html"


class EmailConversationObservablePresenter(ObservablePresenter):
    """Presenter for EmailConversationObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/email_conversation_observable.html"


class FileObservablePresenter(ObservablePresenter):
    """Presenter for FileObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/file_observable.html"

    @property
    def available_actions(self) -> list:
        from saq.gui.observable_actions.file import (
            ObservableActionDownloadFileAsZip,
            ObservableActionViewAsHex,
            ObservableActionViewAsText,
            ObservableActionViewInBrowser,
            ObservableActionFileSendTo,
            ObservableActionFileRender,
        )
        from saq.gui import ObservableActionSeparator

        result = [
            ObservableActionDownloadFileAsZip(),
            ObservableActionViewAsHex(),
            ObservableActionViewAsText(),
            ObservableActionViewInBrowser(),
            ObservableActionFileSendTo(),
            ObservableActionFileRender(),
            ObservableActionSeparator(),
        ]
        result.extend(super().available_actions)
        return result

class FileLocationObservablePresenter(ObservablePresenter):
    """Presenter for FileLocationObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/file_location_observable.html"

    @property
    def available_actions(self) -> list:
        from saq.gui.observable_actions.file import ObservableActionCollectFile
        from saq.gui import ObservableActionSeparator

        result = [ObservableActionCollectFile(), ObservableActionSeparator()]
        result.extend(super().available_actions)
        return result


class IPv4ObservablePresenter(ObservablePresenter):
    """Presenter for IPv4Observable."""

    @property
    def template_path(self) -> str:
        return "analysis/ipv4_observable.html"


class FQDNObservablePresenter(ObservablePresenter):
    """Presenter for FQDNObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/fqdn_observable.html"


class IndicatorObservablePresenter(ObservablePresenter):
    """Presenter for IndicatorObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/indicator_observable.html"


class UserObservablePresenter(ObservablePresenter):
    """Presenter for UserObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/user_observable.html"


class SHA1ObservablePresenter(ObservablePresenter):
    """Presenter for SHA1Observable."""

    @property
    def template_path(self) -> str:
        return "analysis/default_observable.html"


class SHA256ObservablePresenter(ObservablePresenter):
    """Presenter for SHA256Observable."""

    @property
    def template_path(self) -> str:
        return "analysis/sha256_observable.html"


# Register the specialized observable presenters
register_observable_presenter("HostnameObservable", HostnameObservablePresenter)
register_observable_presenter("EmailAddressObservable", EmailAddressObservablePresenter)
register_observable_presenter(
    "EmailConversationObservable", EmailConversationObservablePresenter
)
register_observable_presenter("FileObservable", FileObservablePresenter)
register_observable_presenter("FileLocationObservable", FileLocationObservablePresenter)
register_observable_presenter("IPv4Observable", IPv4ObservablePresenter)
register_observable_presenter("FQDNObservable", FQDNObservablePresenter)
register_observable_presenter("IndicatorObservable", IndicatorObservablePresenter)
register_observable_presenter("UserObservable", UserObservablePresenter)
register_observable_presenter("SHA1Observable", SHA1ObservablePresenter)
register_observable_presenter("SHA256Observable", SHA256ObservablePresenter)
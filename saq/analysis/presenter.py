from typing import TYPE_CHECKING, Type

from saq.database.database_observable import observable_is_set_for_detection

if TYPE_CHECKING:
    from saq.gui import ObservableAction

# Registry for custom presenter classes
_PRESENTER_REGISTRY: dict[str, Type["AnalysisPresenter"]] = {}


def register_presenter(
    analysis_class_name: str, presenter_class: Type["AnalysisPresenter"]
):
    """Register a custom presenter for a specific analysis class."""
    _PRESENTER_REGISTRY[analysis_class_name] = presenter_class


def create_analysis_presenter(analysis):
    """Factory function to create an appropriate presenter for an Analysis object."""
    analysis_class_name = type(analysis).__name__
    presenter_class = _PRESENTER_REGISTRY.get(analysis_class_name, AnalysisPresenter)
    return presenter_class(analysis)


class AnalysisPresenter:
    """Handles presentation logic for Analysis objects, separating UI concerns from domain logic."""

    def __init__(self, analysis):
        """Initialize presenter with an Analysis instance."""
        from saq.analysis.analysis import Analysis

        assert isinstance(analysis, Analysis)
        self._analysis = analysis

    @property
    def should_render(self) -> bool:
        """Returns True if the Analysis should be rendered in the GUI."""
        if self._analysis.summary is not None:
            return True

        if len(self._analysis.observables) > 0:
            return True

        return False

    @property
    def display_name(self) -> str:
        """Returns a visual name to display in the GUI."""
        if self._analysis.summary is not None:
            return self._analysis.summary

        # if we don't have a summary then just return the name of the class
        return type(self._analysis).__name__

    @property
    def is_drillable(self) -> bool:
        """Returns True if the user is intended to click on the Analysis for more details."""
        return True

    @property
    def template_path(self) -> str:
        """Returns the template path to use when rendering this analysis."""
        return "analysis/default_template.html"

    @property
    def details(self):
        """Returns the details object to be used when displaying in the GUI."""
        return self._analysis.details

    # Delegate access to the underlying analysis object for any other properties needed
    def __getattr__(self, name):
        """Delegate any missing attributes to the underlying analysis object."""
        return getattr(self._analysis, name)


# Specialized presenters for specific analysis types that previously overrode jinja properties


class TagAnalysisPresenter(AnalysisPresenter):
    """Presenter for TagAnalysis - doesn't render in GUI."""

    @property
    def should_render(self) -> bool:
        return False


class UserTagAnalysisPresenter(AnalysisPresenter):
    """Presenter for UserTagAnalysis - doesn't render in GUI."""

    @property
    def should_render(self) -> bool:
        return False


class UserAnalysisPresenter(AnalysisPresenter):
    """Presenter for UserAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/user.html"


class AssetAnalysisPresenter(AnalysisPresenter):
    """Presenter for AssetAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/asset_analysis.html"


class BaseAPIAnalysisPresenter(AnalysisPresenter):
    """Presenter for BaseAPIAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/api_analysis.html"


class WhoisAnalysisPresenter(AnalysisPresenter):
    """Presenter for WhoisAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/whois.html"


class NetworkIdentifierAnalysisPresenter(AnalysisPresenter):
    """Presenter for NetworkIdentifierAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/network_identifier.html"


class X509AnalysisPresenter(AnalysisPresenter):
    """Presenter for X509Analysis."""

    @property
    def template_path(self) -> str:
        return "analysis/x509_file_analysis.html"


class YaraAnalysisPresenter(AnalysisPresenter):
    """Presenter for YaraAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/yara_analysis.html"


class EmailAnalysisPresenter(AnalysisPresenter):
    """Presenter for EmailAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/email_analysis.html"


class IPDBAnalysisPresenter(AnalysisPresenter):
    """Presenter for IPDBAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/ipdb_analysis.html"


class BinaryAnalysisPresenter(AnalysisPresenter):
    """Presenter for BinaryAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/default_template.html"


class GUIAlertPresenter(AnalysisPresenter):
    """Presenter for GUIAlert that handles complex template logic."""

    @property
    def template_path(self) -> str:
        """Returns the template path with complex logic from the original GUIAlert."""
        # Check if this is a GUIAlert with specific template logic
        if not hasattr(self._analysis, "alert_type"):
            return "analysis/alert.html"

        # Complex template selection logic from original GUIAlert
        try:
            from saq.configuration import get_config_value
            from saq.constants import (
                CONFIG_CUSTOM_ALERTS,
                CONFIG_CUSTOM_ALERTS_BACKWARDS_COMPAT,
                CONFIG_CUSTOM_ALERTS_TEMPLATE_DIR,
                CONFIG_CUSTOM_ALERTS_DIR,
            )
            from saq.environment import get_base_dir
            import os
            import logging

            logging.debug(
                f"checking for custom template for {self._analysis.alert_type}"
            )

            # first check backward compatible config to see if there is already a template set for this alert_type value
            backwards_compatible = get_config_value(
                CONFIG_CUSTOM_ALERTS_BACKWARDS_COMPAT, self._analysis.alert_type
            )
            if backwards_compatible:
                logging.debug(
                    "using backwards compatible template %s for %s",
                    backwards_compatible,
                    self._analysis.alert_type,
                )
                return backwards_compatible

            base_template_dir = get_config_value(
                CONFIG_CUSTOM_ALERTS, CONFIG_CUSTOM_ALERTS_TEMPLATE_DIR
            )
            dirs = get_config_value(
                CONFIG_CUSTOM_ALERTS, CONFIG_CUSTOM_ALERTS_DIR
            ).split(";")

            # gather all available custom templates into dictionary with their parent directory
            files = {}
            for directory in dirs:
                files.update(
                    {
                        file: directory
                        for file in os.listdir(
                            os.path.join(get_base_dir(), base_template_dir, directory)
                        )
                    }
                )

            # alert_type switch logic
            alert_subtype = self._analysis.alert_type.replace(" - ", "_").replace(
                " ", "_"
            )
            while True:
                if f"{alert_subtype}.html" in files.keys():
                    logging.debug(f"found custom template {alert_subtype}.html")
                    return os.path.join(
                        files[f"{alert_subtype}.html"], f"{alert_subtype}.html"
                    )

                if "_" not in alert_subtype:
                    break
                else:
                    alert_subtype = alert_subtype.rsplit("_", 1)[0]

            logging.debug(
                f"template not found for {self._analysis.alert_type}; defaulting to alert.html"
            )

        except Exception as e:
            logging.debug(e)
            pass

        # Default fallback
        return "analysis/alert.html"

    @property
    def analysis_overview(self) -> str:
        """Returns HTML analysis overview."""
        result = "<ul>"
        for observable in self._analysis.observables:
            result += "<li>{0}</li>".format(observable)
        result += "</ul>"
        return result

    @property
    def event_time(self) -> str:
        """Returns formatted event time."""
        from saq.constants import EVENT_TIME_FORMAT_TZ

        if hasattr(self._analysis, "event_time") and self._analysis.event_time:
            return self._analysis.event_time.strftime(EVENT_TIME_FORMAT_TZ)
        return ""


# Register the specialized presenters
register_presenter("TagAnalysis", TagAnalysisPresenter)
register_presenter("UserTagAnalysis", UserTagAnalysisPresenter)
register_presenter("UserAnalysis", UserAnalysisPresenter)
register_presenter("AssetAnalysis", AssetAnalysisPresenter)
register_presenter("BaseAPIAnalysis", BaseAPIAnalysisPresenter)
register_presenter("WhoisAnalysis", WhoisAnalysisPresenter)
register_presenter("NetworkIdentifierAnalysis", NetworkIdentifierAnalysisPresenter)
register_presenter("X509Analysis", X509AnalysisPresenter)
register_presenter("YaraAnalysis", YaraAnalysisPresenter)
register_presenter("EmailAnalysis", EmailAnalysisPresenter)
register_presenter("IPDBAnalysis", IPDBAnalysisPresenter)
register_presenter("BinaryAnalysis", BinaryAnalysisPresenter)
register_presenter("GUIAlert", GUIAlertPresenter)
register_presenter("Alert", GUIAlertPresenter)
register_presenter("RootAnalysis", GUIAlertPresenter)


# Observable Presentation Logic

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

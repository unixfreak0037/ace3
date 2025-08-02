import logging
import os
import pytz
from saq import RootAnalysis
from saq.analysis.presenter import register_analysis_presenter, AnalysisPresenter
from saq.configuration.config import get_config_value, get_config_value_as_list
from saq.constants import CONFIG_CUSTOM_ALERTS, CONFIG_CUSTOM_ALERTS_BACKWARDS_COMPAT, CONFIG_CUSTOM_ALERTS_DIR, CONFIG_CUSTOM_ALERTS_TEMPLATE_DIR, EVENT_TIME_FORMAT_TZ
from saq.database.model import Alert
from saq.environment import get_base_dir


class GUIAlert(Alert):

    def _initialize(self, *args, **kwargs):
        super()._initialize(*args, **kwargs)

        # the timezone we use to display datetimes, defaults to UTC
        self.display_timezone = pytz.utc

    def get_metadata_json(self) -> dict:
        """Returns a dict of alert metadata intended to be used by client API calls."""
        return {
            "disposition": self.disposition,
            "disposition_user_id": self.disposition_user_id,
            "disposition_user_name": self.disposition_user.gui_display if self.disposition_user_id is not None else None,
            "owner_id": self.owner_id,
            "owner_name": self.owner.gui_display if self.owner_id is not None else None,
        }

    """Extends the Alert class to add functionality specific to the GUI."""
    @property
    def jinja_template_path(self):
        # is there a custom template for this alert type that we can use?
        try:
            logging.debug(f"checking for custom template for {self.alert_type}")

            # first check backward compatible config to see if there is already a template set for this alert_type value
            backwards_compatible = get_config_value(CONFIG_CUSTOM_ALERTS_BACKWARDS_COMPAT, self.alert_type)
            if backwards_compatible:
                logging.debug("using backwards compatible template %s for %s", backwards_compatible, self.alert_type)
                return backwards_compatible

            base_template_dir = get_config_value(CONFIG_CUSTOM_ALERTS, CONFIG_CUSTOM_ALERTS_TEMPLATE_DIR)
            dirs = get_config_value_as_list(CONFIG_CUSTOM_ALERTS, CONFIG_CUSTOM_ALERTS_DIR, sep=";")

            # gather all available custom templates into dictionary with their parent directory
            # Ex. {custom1: '/custom', custom2: '/custom', custom3: '/custom/site'}
            files = {}
            for directory in dirs:
                files.update({file: directory for file in os.listdir(os.path.join(get_base_dir(), base_template_dir, directory))})

            """ 
                alert_type switch logic:
                0. alert_type should be ' - ' separated in 'decreasing' subtype order: 
                    Ex. 'tool - app - query' or 'hunter - splunk - aws' 
                1. alert_subtype = alert_type tranformed to 'desired' HTML format
                    Ex. 'tool_app_query' or 'hunter_splunk_aws'
                2. Check whether desired filename (ex. 'tool_app_query.html') exists in our dictionary of files 
                    if yes --> return path to that file
                    if not --> Step 3 
                3. Truncate alert_type from last '_' and repeat step 2 (ex. check for 'tool_app.html' or 'hunter_splunk.html')
                    If fully truncated alert_type ('tool.html' or 'hunter.html') not found, return default view "analysis/alert.html"
            """

            alert_subtype = self.alert_type.replace(' - ', '_').replace(' ', '_')
            while True:
                if f'{alert_subtype}.html' in files.keys():

                    logging.debug(f"found custom template {alert_subtype}.html")
                    return os.path.join(files[f'{alert_subtype}.html'], f'{alert_subtype}.html')

                if '_' not in alert_subtype:
                    break
                else:
                    alert_subtype = alert_subtype.rsplit('_', 1)[0]

            logging.debug(f" template not found for {self.alert_type}; defaulting to alert.html")

        except Exception as e:
            logging.debug(e)
            pass

        # otherwise just return the default
        return "analysis/alert.html"

    @property
    def jinja_analysis_overview(self):
        result = '<ul>'
        for observable in self.observables:
            result += '<li>{0}</li>'.format(observable)
        result += '</ul>'

        return result

    @property
    def jinja_event_time(self):
        return self.event_time.strftime(EVENT_TIME_FORMAT_TZ)

    @property
    def display_insert_date(self):
        """Returns the insert date in the timezone specified by display_timezone."""
        return self.insert_date.astimezone(self.display_timezone).strftime(EVENT_TIME_FORMAT_TZ)

    @property
    def display_disposition_time(self):
        """Returns the disposition time in the timezone specified by display_timezone."""
        return self.disposition_time.astimezone(self.display_timezone).strftime(EVENT_TIME_FORMAT_TZ)

    @property
    def display_event_time(self):
        """Returns the time the alert was observed (which may be different from when the alert was inserted
           into the database."""
        return self.event_time.astimezone(self.display_timezone).strftime(EVENT_TIME_FORMAT_TZ)

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

register_analysis_presenter(RootAnalysis, GUIAlertPresenter)
#register_analysis_presenter(GUIAlert, GUIAlertPresenter)
#register_analysis_presenter(Alert, GUIAlertPresenter)

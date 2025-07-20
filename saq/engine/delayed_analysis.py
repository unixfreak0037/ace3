import logging

from saq.analysis.root import RootAnalysis
from saq.engine.configuration_manager import ConfigurationManager


class DelayedAnalysisRequest:
    """Encapsulates a request for delayed analysis."""

    def __init__(
        self,
        uuid,
        observable_uuid,
        analysis_module,
        next_analysis,
        storage_dir,
        database_id=None,
    ):

        assert isinstance(uuid, str) and uuid
        assert isinstance(observable_uuid, str) and observable_uuid
        assert isinstance(analysis_module, str) and analysis_module
        assert isinstance(storage_dir, str) and storage_dir

        self.uuid = uuid
        self.observable_uuid = observable_uuid
        self.analysis_module = analysis_module
        self.next_analysis = next_analysis
        self.database_id = database_id
        self.storage_dir = storage_dir

        self.root = None

    def load(self, configuration_manager: ConfigurationManager):

        logging.debug(f"loading {self}")
        self.root = RootAnalysis(uuid=self.uuid, storage_dir=self.storage_dir)
        self.root.load()

        self.observable = self.root.get_observable(self.observable_uuid)
        if self.observable is None:
            logging.error(
                f"unable to load observable {self.observable_uuid} for {self}"
            )

        try:
            self.analysis_module = configuration_manager.analysis_module_name_mapping[
                self.analysis_module
            ]
        except KeyError:
            logging.error(f"missing analysis module {self.analysis_module} for {self}")

        self.analysis = self.observable.get_analysis(
            self.analysis_module.generated_analysis_type,
            instance=self.analysis_module.instance,
        )
        if self.analysis is None:
            logging.error(
                f"unable to load analysis {self.analysis_module.generated_analysis_type} for {self}"
            )

    def __str__(self):
        return "DelayedAnalysisRequest for {} by {} @ {}".format(
            self.uuid, self.analysis_module, self.next_analysis
        )

    def __repr__(self):
        return self.__str__()

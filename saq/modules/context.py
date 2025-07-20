from typing import Optional
from saq.analysis.interfaces import RootAnalysisInterface
from saq.configuration.interfaces import ConfigInterface
from saq.filesystem.interfaces import FileSystemInterface

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from saq.modules.state_repository import StateRepositoryInterface
    from saq.modules.interfaces import AnalysisCacheStrategyInterface
    from saq.engine.delayed_analysis_interface import DelayedAnalysisInterface
    from saq.engine.configuration_manager import ConfigurationManager
    from saq.engine.engine_configuration import EngineConfiguration


from datetime import datetime


class AnalysisModuleContext:
    """Context object that holds all dependencies for analysis modules."""

    def __init__(self,
                 delayed_analysis_interface: Optional["DelayedAnalysisInterface"] = None,
                 root: Optional[RootAnalysisInterface] = None,
                 configuration_manager: Optional["ConfigurationManager"] = None,
                 config: Optional[ConfigInterface] = None,
                 filesystem: Optional[FileSystemInterface] = None,
                 state_repository: Optional["StateRepositoryInterface"] = None,
                 cache_strategy: Optional["AnalysisCacheStrategyInterface"] = None):

        self._delayed_analysis_interface: Optional["DelayedAnalysisInterface"] = delayed_analysis_interface
        self._root: Optional[RootAnalysisInterface] = root
        self._configuration_manager: Optional["ConfigurationManager"] = configuration_manager
        self._config: Optional[ConfigInterface] = config
        self._filesystem: Optional[FileSystemInterface] = filesystem
        self.state_repository: Optional["StateRepositoryInterface"] = state_repository
        self.cache_strategy: Optional["AnalysisCacheStrategyInterface"] = cache_strategy

        # something might try to cancel an analysis execution
        self.cancel_analysis_flag: bool = False

        # sometimes a module can depend on another service that is failing
        # when that happens we can trigger "cooldown periods" where we skip executing this module until some time
        # has elapsed

        # the time at which the cooldown expires (None if no cooldown is in effect)
        self.cooldown_timeout: Optional[datetime] = None

    @property
    def delayed_analysis_interface(self) -> "DelayedAnalysisInterface":
        """Returns the delayed analysis interface."""
        if not self._delayed_analysis_interface:
            raise RuntimeError("delayed analysis interface is not set")

        return self._delayed_analysis_interface

    @property
    def root(self) -> RootAnalysisInterface:
        """Returns the root analysis instance."""
        if not self._root:
            raise RuntimeError("root is not set")

        return self._root

    @property
    def configuration_manager(self) -> "ConfigurationManager":
        """Returns the configuration manager instance."""
        if not self._configuration_manager:
            raise RuntimeError("configuration manager is not set")

        return self._configuration_manager

    @property
    def engine_configuration(self) -> "EngineConfiguration":
        """Returns the engine configuration instance."""
        if not self._configuration_manager:
            raise RuntimeError("configuration manager is not set")

        if not self._configuration_manager.config:
            raise RuntimeError("engine configuration is not set")

        return self._configuration_manager.config

    @property
    def config(self) -> ConfigInterface:
        """Returns the config instance."""
        if not self._config:
            raise RuntimeError("config is not set")

        return self._config

    @property
    def filesystem(self) -> FileSystemInterface:
        """Returns the filesystem instance."""
        if not self._filesystem:
            raise RuntimeError("filesystem is not set")

        return self._filesystem
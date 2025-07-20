from typing import Protocol


class EngineInterface(Protocol):
    """Interface for the analysis engine."""

    @property
    def shutdown(self) -> bool:
        """Returns True if the engine is shutting down."""
        ...

    @property
    def controlled_shutdown(self) -> bool:
        """Returns True if the engine is doing a controlled shutdown."""
        ...

    def delay_analysis(
        self,
        root,
        observable,
        analysis,
        module,
        hours=None,
        minutes=None,
        seconds=None,
        timeout_hours=None,
        timeout_minutes=None,
        timeout_seconds=None,
    ) -> bool:
        """Delay analysis for the specified time."""
        ...

    def is_module_enabled(self, module_or_analysis) -> bool:
        """Check if a module or analysis type is enabled."""
        ...

    def cancel_analysis(self):
        """Cancel the current analysis."""
        ...

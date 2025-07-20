class EngineAdapter:
    """Adapter that wraps an Engine to implement EngineInterface."""

    def __init__(self, engine):
        self._engine = engine

    @property
    def shutdown(self) -> bool:
        return self._engine.shutdown

    @property
    def controlled_shutdown(self) -> bool:
        return self._engine.controlled_shutdown

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
        return self._engine.delay_analysis(
            root,
            observable,
            analysis,
            module,
            hours=hours,
            minutes=minutes,
            seconds=seconds,
            timeout_hours=timeout_hours,
            timeout_minutes=timeout_minutes,
            timeout_seconds=timeout_seconds,
        )

    def is_module_enabled(self, module_or_analysis) -> bool:
        return self._engine.is_module_enabled(module_or_analysis)

    def cancel_analysis(self):
        return self._engine.cancel_analysis()

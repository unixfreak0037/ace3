from typing import TYPE_CHECKING, Optional
from saq.engine.delayed_analysis_interface import DelayedAnalysisInterface
from saq.analysis.interfaces import ObservableInterface, AnalysisInterface
from saq.modules.interfaces import AnalysisModuleInterface

if TYPE_CHECKING:
    from saq.engine.worker import Worker


class DelayedAnalysisAdapter(DelayedAnalysisInterface):
    """Adapter that implements DelayedAnalysisInterface using a Worker instance."""
    
    def __init__(self, worker: "Worker"):
        """Initialize the adapter with a worker instance.
        
        Args:
            worker: The worker instance to use for delayed analysis
        """
        self.worker = worker
    
    def delay_analysis(
        self,
        root,
        observable: ObservableInterface,
        analysis: AnalysisInterface,
        analysis_module: AnalysisModuleInterface,
        hours: Optional[int] = None,
        minutes: Optional[int] = None,
        seconds: Optional[int] = None,
        timeout_hours: Optional[int] = None,
        timeout_minutes: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
    ) -> bool:
        """Schedule delayed analysis for the given observable and analysis.
        
        Args:
            root: The root analysis object
            observable: The observable to analyze
            analysis: The analysis object
            analysis_module: The analysis module to execute
            hours: Hours to delay
            minutes: Minutes to delay  
            seconds: Seconds to delay
            timeout_hours: Timeout hours
            timeout_minutes: Timeout minutes
            timeout_seconds: Timeout seconds
            
        Returns:
            True if delayed analysis was successfully scheduled, False otherwise
        """
        try:
            # Delegate the delayed analysis scheduling to the worker
            return self.worker.delay_analysis(
                root=root,
                observable=observable,
                analysis=analysis,
                analysis_module=analysis_module,
                hours=hours,
                minutes=minutes,
                seconds=seconds,
                timeout_hours=timeout_hours,
                timeout_minutes=timeout_minutes,
                timeout_seconds=timeout_seconds,
            )
        except Exception as e:
            # Log the error and return False to indicate failure
            import logging
            logging.error(f"Failed to schedule delayed analysis: {e}")
            return False

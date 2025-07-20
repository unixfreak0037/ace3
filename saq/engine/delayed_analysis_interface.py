from typing import Optional, Protocol
from saq.analysis.interfaces import ObservableInterface, AnalysisInterface
from saq.modules.interfaces import AnalysisModuleInterface


class DelayedAnalysisInterface(Protocol):
    """Protocol defining the interface for delayed analysis functionality."""
    
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
        ...

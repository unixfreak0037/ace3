import logging
from typing import Dict, List, Callable, Optional
from saq.constants import (
    EVENT_ANALYSIS_ADDED, 
    EVENT_GLOBAL_ANALYSIS_ADDED, 
    EVENT_GLOBAL_OBSERVABLE_ADDED, 
    EVENT_GLOBAL_TAG_ADDED, 
    EVENT_OBSERVABLE_ADDED, 
    EVENT_TAG_ADDED,
    VALID_EVENTS
)


class AnalysisEventBus:
    """Centralized event management system for analysis operations.
    
    Handles both local and global event dispatching, managing event listeners
    and propagation throughout the analysis hierarchy.
    """
    
    def __init__(self):
        # Maps event types to lists of callback functions
        self._event_listeners: Dict[str, List[Callable]] = {}
        
    def add_event_listener(self, event: str, callback: Callable) -> None:
        """Add an event listener for a specific event type.
        
        Args:
            event: The event type to listen for
            callback: The callback function to invoke when the event is fired
        """
        assert isinstance(event, str), f"Event must be a string, got {type(event)}"
        assert callable(callback), f"Callback must be callable, got {type(callback)}"
        assert event in VALID_EVENTS, f"Event {event} not in VALID_EVENTS"
        
        if event not in self._event_listeners:
            self._event_listeners[event] = []
            
        if callback not in self._event_listeners[event]:
            self._event_listeners[event].append(callback)
            
    def remove_event_listener(self, event: str, callback: Callable) -> None:
        """Remove an event listener for a specific event type.
        
        Args:
            event: The event type to stop listening for
            callback: The callback function to remove
        """
        if event in self._event_listeners and callback in self._event_listeners[event]:
            self._event_listeners[event].remove(callback)
            
    def clear_event_listeners(self, event: Optional[str] = None) -> None:
        """Clear event listeners.
        
        Args:
            event: If specified, clear listeners for this event only. 
                  If None, clear all listeners.
        """
        if event is None:
            self._event_listeners.clear()
        elif event in self._event_listeners:
            self._event_listeners[event].clear()
            
    def fire_event(self, source, event: str, *args, **kwargs) -> None:
        """Fire an event to all registered listeners.
        
        Args:
            source: The object that triggered the event
            event: The event type being fired
            *args: Additional arguments to pass to event listeners
            **kwargs: Additional keyword arguments to pass to event listeners
        """
        assert event in VALID_EVENTS, f"Event {event} not in VALID_EVENTS"
        
        if event in self._event_listeners:
            for callback in self._event_listeners[event]:
                try:
                    callback(source, event, *args, **kwargs)
                except Exception as e:
                    logging.error(f"Error in event listener for {event}: {e}")
                    
    def fire_global_events(self, source, event_type: str, *args, **kwargs) -> None:
        """Handle the conversion from local events to global events.
        
        This method replicates the logic from RootAnalysis._fire_global_events,
        transforming local events (TAG_ADDED, OBSERVABLE_ADDED, ANALYSIS_ADDED)
        into their global equivalents and setting up cascading event listeners.
        
        Args:
            source: The object that triggered the original event
            event_type: The local event type that was fired
            *args: Additional arguments from the original event
            **kwargs: Additional keyword arguments from the original event
        """
        if event_type == EVENT_TAG_ADDED:
            self.fire_event(source, EVENT_GLOBAL_TAG_ADDED, *args, **kwargs)
            
        elif event_type == EVENT_OBSERVABLE_ADDED:
            observable = args[0]
            # Set up cascading event listeners on the newly added observable
            self.setup_observable_event_propagation(observable)
            self.fire_event(source, EVENT_GLOBAL_OBSERVABLE_ADDED, *args, **kwargs)
            
        elif event_type == EVENT_ANALYSIS_ADDED:
            analysis = args[0]
            # Set up cascading event listeners on the newly added analysis
            self.setup_analysis_event_propagation(analysis)
            self.fire_event(source, EVENT_GLOBAL_ANALYSIS_ADDED, *args, **kwargs)
            
        else:
            logging.error(f"Unsupported global event type: {event_type}")
            
    def setup_global_event_propagation(self, root_analysis) -> None:
        """Set up initial global event propagation for a root analysis.
        
        This method sets up the initial event listeners that convert local events
        to global events, replicating the setup done in RootAnalysis.__init__.
        
        Args:
            root_analysis: The RootAnalysis object to set up event propagation for
        """
        root_analysis.add_event_listener(EVENT_TAG_ADDED, self.fire_global_events)
        root_analysis.add_event_listener(EVENT_OBSERVABLE_ADDED, self.fire_global_events)
        
    def setup_observable_event_propagation(self, observable) -> None:
        """Set up event propagation for a newly deserialized observable.
        
        This method replicates the event listener setup done when observables
        are loaded from JSON in RootAnalysis.
        
        Args:
            observable: The Observable object to set up event propagation for
        """
        observable.add_event_listener(EVENT_ANALYSIS_ADDED, self.fire_global_events)
        observable.add_event_listener(EVENT_TAG_ADDED, self.fire_global_events)
        
    def setup_analysis_event_propagation(self, analysis) -> None:
        """Set up event propagation for a newly loaded analysis.
        
        This method replicates the event listener setup done when analysis objects
        are loaded from JSON in Observable._load_analysis.
        
        Args:
            analysis: The Analysis object to set up event propagation for
        """
        analysis.add_event_listener(EVENT_OBSERVABLE_ADDED, self.fire_global_events)
        analysis.add_event_listener(EVENT_TAG_ADDED, self.fire_global_events)
        
    def get_listener_count(self, event: Optional[str] = None) -> int:
        """Get the number of listeners for an event or all events.
        
        Args:
            event: If specified, get count for this event only.
                  If None, get total count across all events.
                  
        Returns:
            Number of event listeners
        """
        if event is None:
            return sum(len(listeners) for listeners in self._event_listeners.values())
        else:
            return len(self._event_listeners.get(event, []))
            
    def has_listeners(self, event: str) -> bool:
        """Check if there are any listeners for a specific event type.
        
        Args:
            event: The event type to check
            
        Returns:
            True if there are listeners for this event, False otherwise
        """
        return event in self._event_listeners and len(self._event_listeners[event]) > 0
    
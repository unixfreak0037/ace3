"""
State repository implementation for analysis modules.

This module implements the Repository Pattern to decouple state management
from the AnalysisModule class, following the Single Responsibility Principle.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from saq.analysis.interfaces import RootAnalysisInterface


class StateRepositoryInterface(ABC):
    """Abstract interface for state repositories."""
    
    @abstractmethod
    def get_state(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get the state for a specific module.
        
        Args:
            module_name: The name/identifier of the module
            
        Returns:
            The state dictionary for the module, or None if no state exists
        """
        pass
    
    @abstractmethod
    def set_state(self, module_name: str, state: Dict[str, Any]) -> None:
        """Set the state for a specific module.
        
        Args:
            module_name: The name/identifier of the module
            state: The state dictionary to store
        """
        pass
    
    @abstractmethod
    def initialize_state(self, module_name: str, initial_state: Dict[str, Any] = None) -> None:
        """Initialize state for a module if it doesn't already exist.
        
        Args:
            module_name: The name/identifier of the module
            initial_state: The initial state to set if no state exists (defaults to empty dict)
        """
        pass
    
    @abstractmethod
    def has_state(self, module_name: str) -> bool:
        """Check if state exists for a specific module.
        
        Args:
            module_name: The name/identifier of the module
            
        Returns:
            True if state exists, False otherwise
        """
        pass
    
    @abstractmethod
    def delete_state(self, module_name: str) -> bool:
        """Delete state for a specific module.
        
        Args:
            module_name: The name/identifier of the module
            
        Returns:
            True if state was deleted, False if no state existed
        """
        pass


class RootAnalysisStateRepository(StateRepositoryInterface):
    """Concrete implementation using RootAnalysis as the state storage backend.
    
    This implementation maintains backward compatibility with the existing
    state storage mechanism in RootAnalysis.state.
    """
    
    def __init__(self, root_analysis: RootAnalysisInterface):
        """Initialize with a reference to the root analysis.
        
        Args:
            root_analysis: The root analysis interface that contains the state storage
        """
        self._root_analysis = root_analysis
    
    def get_state(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get the state for a specific module from root analysis state."""
        try:
            return self._root_analysis.state[module_name]
        except KeyError:
            return None
    
    def set_state(self, module_name: str, state: Dict[str, Any]) -> None:
        """Set the state for a specific module in root analysis state."""
        self._root_analysis.state[module_name] = state
    
    def initialize_state(self, module_name: str, initial_state: Dict[str, Any] = None) -> None:
        """Initialize state for a module if it doesn't already exist."""
        if initial_state is None:
            initial_state = {}
            
        if module_name not in self._root_analysis.state:
            self._root_analysis.state[module_name] = initial_state
    
    def has_state(self, module_name: str) -> bool:
        """Check if state exists for a specific module."""
        return module_name in self._root_analysis.state
    
    def delete_state(self, module_name: str) -> bool:
        """Delete state for a specific module."""
        if module_name in self._root_analysis.state:
            del self._root_analysis.state[module_name]
            return True
        return False


class InMemoryStateRepository(StateRepositoryInterface):
    """In-memory implementation for testing or temporary state storage."""
    
    def __init__(self):
        """Initialize with an empty state dictionary."""
        self._state_storage: Dict[str, Dict[str, Any]] = {}
    
    def get_state(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get the state for a specific module from memory."""
        return self._state_storage.get(module_name)
    
    def set_state(self, module_name: str, state: Dict[str, Any]) -> None:
        """Set the state for a specific module in memory."""
        self._state_storage[module_name] = state
    
    def initialize_state(self, module_name: str, initial_state: Dict[str, Any] = None) -> None:
        """Initialize state for a module if it doesn't already exist."""
        if initial_state is None:
            initial_state = {}
            
        if module_name not in self._state_storage:
            self._state_storage[module_name] = initial_state
    
    def has_state(self, module_name: str) -> bool:
        """Check if state exists for a specific module."""
        return module_name in self._state_storage
    
    def delete_state(self, module_name: str) -> bool:
        """Delete state for a specific module."""
        if module_name in self._state_storage:
            del self._state_storage[module_name]
            return True
        return False


class StateRepositoryFactory:
    """Factory for creating appropriate state repository instances."""
    
    @staticmethod
    def create_root_analysis_repository(root_analysis: RootAnalysisInterface) -> StateRepositoryInterface:
        """Create a repository that uses RootAnalysis for state storage.
        
        Args:
            root_analysis: The root analysis interface to use for storage
            
        Returns:
            A RootAnalysisStateRepository instance
        """
        return RootAnalysisStateRepository(root_analysis)
    
    @staticmethod
    def create_in_memory_repository() -> StateRepositoryInterface:
        """Create an in-memory repository for testing or temporary use.
        
        Returns:
            An InMemoryStateRepository instance
        """
        return InMemoryStateRepository() 
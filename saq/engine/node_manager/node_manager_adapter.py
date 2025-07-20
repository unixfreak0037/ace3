from datetime import datetime
from typing import Optional

from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface


class NodeManagerAdapter(NodeManagerInterface):
    """Adapter that implements NodeManagerInterface and delegates to NodeManager."""
    
    def __init__(
        self,
        node_manager: NodeManagerInterface,
    ):
        """Initialize the NodeManagerAdapter.
        
        Args:
            node_manager: Any implementation of NodeManagerInterface to delegate operations to
        """
        self._node_manager = node_manager

    @property
    def configuration_manager(self) -> ConfigurationManager:
        """Returns the configuration manager."""
        return getattr(self._node_manager, 'configuration_manager')

    @property
    def config(self) -> object:
        """Returns the configuration object."""
        return getattr(self._node_manager, 'config')

    @property
    def node_status_update_frequency(self) -> int:
        """Returns the node status update frequency."""
        return getattr(self._node_manager, 'node_status_update_frequency')

    @property
    def next_status_update_time(self) -> Optional[datetime]:
        """Returns the next status update time."""
        return getattr(self._node_manager, 'next_status_update_time')

    @property
    def hostname(self) -> str:
        """Returns the hostname."""
        return getattr(self._node_manager, 'hostname')

    @property
    def target_nodes(self) -> list[str]:
        """List of nodes this engine will pull work from."""
        return self._node_manager.target_nodes
    
    @property
    def local_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine supports."""
        return self._node_manager.local_analysis_modes
    
    @property
    def excluded_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine excludes."""
        return self._node_manager.excluded_analysis_modes
    
    def should_update_node_status(self) -> bool:
        """Returns True if it's time to update node status."""
        return self._node_manager.should_update_node_status()
    
    def update_node_status(self) -> None:
        """Updates the last_update field of the node table for this node."""
        return self._node_manager.update_node_status()
    
    def initialize_node(self) -> None:
        """Initialize this node in the database and configure analysis modes."""
        return self._node_manager.initialize_node()
    
    def execute_primary_node_routines(self) -> None:
        """Executes primary node routines and may become the primary node if no other node has done so."""
        return self._node_manager.execute_primary_node_routines()
    
    def update_node_status_and_execute_primary_routines(self) -> None:
        """Updates node status and executes primary node routines if needed."""
        return self._node_manager.update_node_status_and_execute_primary_routines()

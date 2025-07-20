import pytest
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.node_manager.node_manager_factory import create_node_manager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface

# TODO create tests for each node manager implementation


@pytest.mark.unit
def test_node_manager_initialization():
    """Test that NodeManager can be initialized properly."""
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    assert isinstance(node_manager, NodeManagerInterface)


@pytest.mark.unit
def test_should_update_node_status():
    """Test the should_update_node_status method."""
    node_manager = create_node_manager(ConfigurationManager(EngineConfiguration()))
    
    # Initially should return True since next_status_update_time is None
    assert node_manager.should_update_node_status() is True 
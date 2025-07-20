from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.node_manager.distributed_node_manager import DistributedNodeManager
from saq.engine.node_manager.local_node_manager import LocalNodeManager
from saq.engine.node_manager.node_manager_adapter import NodeManagerAdapter
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.enums import EngineType


def create_node_manager(configuration_manager: ConfigurationManager) -> NodeManagerInterface:
    if configuration_manager.config.engine_type == EngineType.LOCAL:
        return NodeManagerAdapter(LocalNodeManager(configuration_manager))
    elif configuration_manager.config.engine_type == EngineType.DISTRIBUTED:
        return NodeManagerAdapter(DistributedNodeManager(configuration_manager))
    else:
        raise ValueError(f"Invalid engine type: {configuration_manager.config.engine_type}")


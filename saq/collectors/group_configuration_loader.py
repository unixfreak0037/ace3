import logging
from typing import Optional

from saq.collectors.remote_node import RemoteNodeGroup
from saq.configuration import get_config, get_config_value, get_config_value_as_boolean, get_config_value_as_int, get_config_value_as_list
from saq.constants import CONFIG_COLLECTION_GROUP_ENABLED, CONFIG_COLLECTION_GROUP_COVERAGE, CONFIG_COLLECTION_GROUP_FULL_DELIVERY, CONFIG_COLLECTION_GROUP_COMPANY_ID, CONFIG_COLLECTION_GROUP_DATABASE, CONFIG_COLLECTION_GROUP_BATCH_SIZE, CONFIG_COLLECTION_GROUP_THREAD_COUNT, CONFIG_COLLECTION_GROUP_TARGET_NODE_AS_COMPANY_ID, CONFIG_COLLECTION_GROUP_TARGET_NODES, G_SAQ_NODE
from saq.environment import g


class GroupConfigurationLoader:
    """Loads RemoteNodeGroup configurations from the ACE configuration file."""
    
    def __init__(self, workload_type_id: int, service_shutdown_event, workload_repository):
        """
        Initialize the GroupConfigurationLoader.
        
        Args:
            workload_type_id: The workload type ID for the groups
            service_shutdown_event: Event for service shutdown signaling
            workload_repository: Repository for creating work distribution groups
        """
        self.workload_type_id = workload_type_id
        self.service_shutdown_event = service_shutdown_event
        self.workload_repository = workload_repository

    def load_groups(self) -> list[RemoteNodeGroup]:
        """
        Loads groups from the ACE configuration file.
        
        Returns:
            List of configured RemoteNodeGroup instances
        """
        remote_node_groups = []
        
        for section in get_config().keys():
            if not section.startswith("collection_group_"):
                continue

            if not get_config_value_as_boolean(section, CONFIG_COLLECTION_GROUP_ENABLED, default=True):
                logging.debug(f"collection group {section} disabled")
                continue

            group_name = section[len("collection_group_"):]
            coverage = get_config_value_as_int(section, CONFIG_COLLECTION_GROUP_COVERAGE)
            full_delivery = get_config_value_as_boolean(section, CONFIG_COLLECTION_GROUP_FULL_DELIVERY)
            company_id = get_config_value_as_int(section, CONFIG_COLLECTION_GROUP_COMPANY_ID)
            database = get_config_value(section, CONFIG_COLLECTION_GROUP_DATABASE)
            batch_size = get_config_value_as_int(section, CONFIG_COLLECTION_GROUP_BATCH_SIZE, default=32)
            thread_count = get_config_value_as_int(section, CONFIG_COLLECTION_GROUP_THREAD_COUNT, default=1)
            
            # XXX get rid of this
            target_node_as_company_id = None
            if get_config_value(section, CONFIG_COLLECTION_GROUP_TARGET_NODE_AS_COMPANY_ID):
                target_node_as_company_id = get_config_value_as_int(section, CONFIG_COLLECTION_GROUP_TARGET_NODE_AS_COMPANY_ID)

            target_nodes = []
            if get_config_value(section, CONFIG_COLLECTION_GROUP_TARGET_NODES):
                for node in get_config_value_as_list(section, CONFIG_COLLECTION_GROUP_TARGET_NODES):
                    if not node:  # pragma: no cover
                        continue

                    if node == "LOCAL":
                        node = g(G_SAQ_NODE)

                    target_nodes.append(node)

            logging.info("loaded group {} coverage {} full_delivery {} company_id {} database {} target_node_as_company_id {} target_nodes {} thread_count {} batch_size {}".format(
                         group_name, coverage, full_delivery, company_id, database, target_node_as_company_id, target_nodes, thread_count, batch_size))

            remote_node_group = self._create_group(
                group_name,
                coverage,
                full_delivery,
                company_id,
                database,
                batch_size=batch_size,
                target_node_as_company_id=target_node_as_company_id,
                target_nodes=target_nodes,
                thread_count=thread_count
            )
            
            remote_node_groups.append(remote_node_group)
            logging.info("added {}".format(remote_node_group))
            
        return remote_node_groups

    def _create_group(
        self, 
        name: str, 
        coverage: int, 
        full_delivery: bool, 
        company_id: int, 
        database: str, 
        batch_size: Optional[int] = 32,
        target_node_as_company_id: Optional[int] = None,
        target_nodes: Optional[list] = None,
        thread_count: Optional[int] = 1
    ) -> RemoteNodeGroup:
        """
        Create a RemoteNodeGroup instance.
        
        Args:
            name: Group name
            coverage: Coverage value
            full_delivery: Whether full delivery is enabled
            company_id: Company ID
            database: Database name
            batch_size: Batch size (default: 32)
            target_node_as_company_id: Target node as company ID (optional)
            target_nodes: List of target nodes (optional)
            thread_count: Thread count (default: 1)
            
        Returns:
            Configured RemoteNodeGroup instance
        """
        group_id = self.workload_repository.create_or_get_work_distribution_group(name)

        remote_node_group = RemoteNodeGroup(
            name, 
            coverage, 
            full_delivery, 
            company_id, 
            database, 
            group_id, 
            self.workload_type_id, 
            self.service_shutdown_event, 
            batch_size=batch_size,
            target_node_as_company_id=target_node_as_company_id,
            target_nodes=target_nodes,
            thread_count=thread_count
        )
        
        return remote_node_group 
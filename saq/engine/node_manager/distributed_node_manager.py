from datetime import datetime, timedelta
import logging
import socket
from typing import Optional

from saq.constants import (
    CONFIG_ENGINE,
    CONFIG_ENGINE_NODE_STATUS_UPDATE_FREQUENCY,
    CONFIG_NODE_TRANSLATION,
    G_API_PREFIX,
    G_SAQ_NODE,
    G_SAQ_NODE_ID,
)
from saq.configuration.config import get_config, get_config_value, get_config_value_as_int
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.database.util.locking import clear_expired_locks
from saq.database.util.node import (
    assign_node_analysis_modes,
    initialize_node,
)
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.environment import g, g_int
from saq.error import report_exception


def update_node_status(
    location: Optional[str] = None, node_id: Optional[int] = None
):
    """Updates the last_update field of the node table for this node."""

    if location is None:
        location = g(G_API_PREFIX)

    if node_id is None:
        node_id = g_int(G_SAQ_NODE_ID)

    try:
        with get_db_connection() as db:
            cursor = db.cursor()
            execute_with_retry(
                db,
                cursor,
                """UPDATE nodes SET last_update = NOW(), location = %s WHERE id = %s""",
                (location, node_id),
                commit=True,
            )

            logging.info(
                "updated node %s (%s)", node_id, location
            )

    except Exception as e:
        logging.error("unable to update node %s status: %s", node_id, e)
        report_exception()


def translate_node(node: str) -> str:
    """Return the correct node taking node translation into account."""
    for key in get_config()[CONFIG_NODE_TRANSLATION].keys():
        src, target = get_config_value(CONFIG_NODE_TRANSLATION, key).split(",")
        if node == src:
            logging.debug("translating node {} to {}".format(node, target))
            return target

    return node


class DistributedNodeManager(NodeManagerInterface):
    """Manages node status updates, primary node election, and local/cluster node configuration for the ACE cluster."""

    def __init__(self, configuration_manager: ConfigurationManager):
        """Initialize the NodeManager with node configuration.
        
        Args:
            target_nodes: List of target nodes this engine will pull work from
            local_analysis_modes: List of analysis modes this engine supports
            excluded_analysis_modes: List of analysis modes this engine excludes
        """

        self.configuration_manager = configuration_manager
        self.config = configuration_manager.config

        # how often do we update the nodes database table for this engine (in seconds)
        self.node_status_update_frequency = get_config_value_as_int(
            CONFIG_ENGINE, CONFIG_ENGINE_NODE_STATUS_UPDATE_FREQUENCY
        )

        # and then when will be the next time we make this update?
        self.next_status_update_time = None

        # we just cache the current hostname of this node here
        self.hostname = socket.gethostname()

    @property
    def target_nodes(self) -> list[str]:
        """List of nodes this engine will pull work from."""
        return self.config.target_nodes

    @property
    def local_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine supports."""
        return self.config.local_analysis_modes
    
    @property
    def excluded_analysis_modes(self) -> list[str]:
        """List of analysis modes this engine excludes."""
        return self.config.excluded_analysis_modes

    def should_update_node_status(self) -> bool:
        """Returns True if it's time to update node status."""
        return (
            self.next_status_update_time is None
            or datetime.now() >= self.next_status_update_time
        )

    def update_node_status(self):
        """Updates the last_update field of the node table for this node."""
        update_node_status(g(G_API_PREFIX), g_int(G_SAQ_NODE_ID))

    def initialize_node(self):
        """Initialize this node in the database and configure analysis modes."""
        # insert this engine as a node (if it isn't already)
        initialize_node()

        # assign analysis mode inclusion and exclusion settings
        assign_node_analysis_modes(
            g_int(G_SAQ_NODE_ID),
            self.local_analysis_modes,
            self.excluded_analysis_modes,
        )

        # clear any outstanding locks left over from a previous execution
        # we use the lock_owner columns of the locks table to determine if any locks are outstanding for this node
        # the format of the value of the column is node-mode-pid
        # ace-qa2.local-email-25203
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM locks WHERE lock_owner LIKE CONCAT(%s, '-%%')",
                (g(G_SAQ_NODE),),
            )
            result = cursor.fetchone()
            if result:
                logging.info(f"clearing {result[0]} locks from previous execution")
                execute_with_retry(
                    db,
                    cursor,
                    "DELETE FROM locks WHERE lock_owner LIKE CONCAT(%s, '-%%')",
                    (g(G_SAQ_NODE),),
                    commit=True,
                )

    def execute_primary_node_routines(self):
        """Executes primary node routines and may become the primary node if no other node has done so."""
        with get_db_connection() as db:
            c = db.cursor()
            try:
                # is there a primary node that has updated node status in the past N seconds
                # where N is 30 + node update status frequency
                c.execute(
                    """
                    SELECT name FROM nodes 
                    WHERE 
                        is_primary = 1 
                        AND TIMESTAMPDIFF(SECOND, last_update, NOW()) < %s
                    """,
                    (self.node_status_update_frequency + 30,),
                )

                primary_node = c.fetchone()

                # is there no primary node at this point?
                if primary_node is None:
                    execute_with_retry(
                        db,
                        c,
                        [
                            "UPDATE nodes SET is_primary = 0",
                            "UPDATE nodes SET is_primary = 1, last_update = NOW() WHERE id = %s",
                        ],
                        [tuple(), (g_int(G_SAQ_NODE_ID),)],
                        commit=True,
                    )
                    primary_node = g(G_SAQ_NODE)
                    logging.info(
                        "this node {} has become the primary node".format(g(G_SAQ_NODE))
                    )
                else:
                    primary_node = primary_node[0]

                # are we the primary node?
                if primary_node != g(G_SAQ_NODE):
                    logging.debug(
                        "node {} is not primary - skipping primary node routines".format(
                            g(G_SAQ_NODE)
                        )
                    )
                    return

                # do primary node stuff
                # clear any outstanding locks
                clear_expired_locks()

            except Exception as e:
                logging.error("error executing primary node routines: {}".format(e))
                report_exception()

    def update_node_status_and_execute_primary_routines(self):
        """Updates node status and executes primary node routines if needed."""
        if self.should_update_node_status():
            self.update_node_status()
            self.execute_primary_node_routines()

            # when will we do this again?
            self.next_status_update_time = datetime.now() + timedelta(
                seconds=self.node_status_update_frequency
            ) 
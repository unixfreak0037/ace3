from enum import Enum

class EngineState(Enum):
    """Enumeration of possible engine states."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    IMMEDIATE_SHUTDOWN = "immediate_shutdown"
    CONTROLLED_SHUTDOWN = "controlled_shutdown"
    STOPPED = "stopped"

class EngineExecutionMode(Enum):
    """Enumeration of possible engine execution modes."""
    NORMAL = "normal" # run until the engine is stopped
    SINGLE_SHOT = "single_shot" # run a single work item and then exit
    UNTIL_COMPLETE = "until_complete" # run until all work is complete

class EngineType(Enum):
    """Enumeration of possible engine types."""
    LOCAL = "local" # single node, single process
    DISTRIBUTED = "distributed" # multiple nodes, multiple processes

class WorkerManagerState(Enum):
    """Enumeration of possible worker states."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    SHUTTING_DOWN = "shutting_down"
    STOPPED = "stopped"

class WorkerStatus(Enum):
    """Enumeration of possible worker statuses."""
    OK = "ok"
    DEAD = "dead"
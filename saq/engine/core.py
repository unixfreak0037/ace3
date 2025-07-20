import logging
import os
import signal
from multiprocessing import Event, Process
from typing import Optional

from saq.constants import (
    G_SAQ_NODE,
)

from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.worker_manager import WorkerManager
from saq.engine.node_manager.node_manager_factory import create_node_manager
from saq.engine.worker import Worker
from saq.environment import g
from saq.error import report_exception
from saq.engine.configuration_manager import ConfigurationManager
from saq.service import ACEServiceInterface
from saq.engine.enums import EngineState, EngineExecutionMode


class Engine():
    """Analysis Correlation Engine with Unified Controller"""

    def __init__(
        self,
        *args,
        config: Optional[EngineConfiguration] = None,
        execution_mode: EngineExecutionMode = EngineExecutionMode.NORMAL,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.state = EngineState.INITIALIZING
        self.execution_mode = execution_mode

        # configuration options
        # ------------------------------------------------------------

        self.config = config or EngineConfiguration(**kwargs)

        # this is used to control the main loop
        self.loop_control_event = Event()

        # set once the engine has started
        self.started_event = Event()
        
        # signal handling flags
        self.sigterm_received = False
        self.sighup_received = False
        self.sigint_received = False

        # initialize configuration manager
        self.configuration_manager = ConfigurationManager(self.config)

        # node manager for cluster and node management
        self.node_manager = create_node_manager(self.configuration_manager)

        # worker manager for managing worker processes
        self.worker_manager = WorkerManager(self.configuration_manager, self.node_manager)

        # make sure these exist
        for directory in [self.config.stats_dir, self.config.work_dir]:
            if directory:
                os.makedirs(directory, exist_ok=True)

        # initialize node configuration and database setup
        self.node_manager.initialize_node()

        # for single threaded execution
        self.single_threaded_worker: Optional[Worker] = None

    def __str__(self):
        return "Engine ({})".format(g(G_SAQ_NODE))

    def _set_state(self, state: EngineState):
        """Sets the state of the engine."""
        if self.state != state:
            self.state = state
            logging.info("engine state changed to {}".format(state))

    def start(self, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Starts the engine. This function does not return until the engine is stopped."""
        logging.info("starting engine controller")
        
        self.main_controller_loop(execution_mode=execution_mode)

    # ------------------------------------------------------------
    # Debug methods
    # ------------------------------------------------------------

    def start_single_shot(self):
        """Starts the engine in single-shot mode. Executes a single work item and then shuts down."""
        self.start(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    def start_nonblocking(self) -> Process:
        """Starts the engine on another process. Returns the created Process object."""
        process = Process(target=self.start)
        process.start()
        return process

    def wait_for_start(self, timeout: Optional[float]=None) -> bool:
        """Waits for the engine to start."""
        return self.started_event.wait(timeout)

    def start_single_threaded(self, analysis_priority_mode: Optional[str]=None, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Starts the engine in single-threaded mode. In this mode a single
        worker is used to execute all work items directly."""
        logging.info("starting engine in single-threaded mode")

        # set single threaded mode
        self.config.single_threaded_mode = True
        
        # run single threaded execution
        self.single_threaded_execution_loop(analysis_priority_mode=analysis_priority_mode, execution_mode=execution_mode)

    # ------------------------------------------------------------
    # control loops
    # ------------------------------------------------------------

    def main_controller_loop(self, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Main controller loop that manages workers and handles signals."""
        logging.info("started engine controller on process {} in mode {}".format(os.getpid(), execution_mode))
        
        # initialize signal handlers
        self.initialize_signal_handlers()
        
        # initialize and start the worker manager
        self.worker_manager.initialize_workers()
        self.worker_manager.start_workers(execution_mode=execution_mode)
        
        logging.info("entering main controller loop")
        self._set_state(EngineState.RUNNING)
        self.started_event.set()

        while True:
            try:
                if execution_mode in [EngineExecutionMode.SINGLE_SHOT, EngineExecutionMode.UNTIL_COMPLETE]:
                    logging.info(f"execution mode {execution_mode} enabled - shutting down after processing")
                    self._controlled_stop()
                    break

                if self.sigint_received:
                    logging.info("received SIGINT")
                    self._controlled_stop()
                    break

                if self.sigterm_received:
                    logging.info("received SIGTERM")
                    self._immediate_stop()
                    break

                # update node status and execute primary node routines if needed
                self.node_manager.update_node_status_and_execute_primary_routines()

                # check workers and restart if needed
                self.worker_manager.check_workers()

                if self.sighup_received:
                    # we re-load the config when we receive SIGHUP
                    #logging.info("reloading engine configuration")
                    self.sighup_received = False

                    # tell the manager to reload the workers
                    self.worker_manager.restart_workers()
                    # and then reload the configuration
                    # TODO: though needs to be put into allowing the configuration to be reloaded
                    #from saq.configuration.parser import load_configuration
                    #load_configuration()

                # if this event is set then we need to exit now
                if self.state in [EngineState.IMMEDIATE_SHUTDOWN, EngineState.CONTROLLED_SHUTDOWN]:
                    break

                # execute loop every second
                self.loop_control_event.wait(1.0)

            except Exception as e:
                logging.error(f"unexpected exception thrown in main controller loop: {e}")
                report_exception()
                self.loop_control_event.wait(1.0)

        logging.info("ended main controller loop")
        self._set_state(EngineState.STOPPED)

    def initialize_single_threaded_worker(self, analysis_priority_mode: Optional[str]=None, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL) -> Worker:
        """Initializes a single-threaded worker."""
        self.single_threaded_worker = Worker("worker-1", self.configuration_manager, self.node_manager, analysis_mode_priority=analysis_priority_mode)
        return self.single_threaded_worker

    def single_threaded_execution_loop(self, analysis_priority_mode: Optional[str]=None, execution_mode: EngineExecutionMode=EngineExecutionMode.NORMAL):
        """Single-threaded execution loop for debugging."""
        logging.info("starting single-threaded execution loop in execution mode {} with priority override {}".format(execution_mode, analysis_priority_mode))

        if not self.single_threaded_worker:
            self.initialize_single_threaded_worker(analysis_priority_mode, execution_mode)

        assert self.single_threaded_worker is not None
        
        # main execution loop
        while True:
            try:
                # execute a single work item
                self.single_threaded_worker.single_threaded_start(execution_mode=execution_mode)
                    
            except KeyboardInterrupt:
                logging.info("received keyboard interrupt")
                break
            except Exception as e:
                logging.error(f"error in single-threaded execution: {e}")
                report_exception()
                break

            break
        
        logging.info("single-threaded execution loop ended")

    def initialize_signal_handlers(self):
        """Initialize signal handlers for the engine process."""
        def handle_sighup(signum, frame):
            self.sighup_received = True

        def handle_sigterm(signum, frame):
            self.sigterm_received = True

        def handle_sigint(signum, frame):
            self.sigint_received = True

        signal.signal(signal.SIGHUP, handle_sighup)
        signal.signal(signal.SIGTERM, handle_sigterm)
        signal.signal(signal.SIGINT, handle_sigint)

    # ------------------------------------------------------------
    # control methods
    # ------------------------------------------------------------

    def _immediate_stop(self):
        """Immediately stop the engine."""
        logging.info("stopping engine NOW")
        self._set_state(EngineState.IMMEDIATE_SHUTDOWN)
        self.worker_manager.immediate_shutdown()

    def _controlled_stop(self):
        """Shutdown the engine in a controlled manner allowing existing jobs to complete."""
        logging.info("stopping engine")
        self._set_state(EngineState.CONTROLLED_SHUTDOWN)
        self.worker_manager.controlled_shutdown()

class EngineService(ACEServiceInterface):
    def __init__(self):
        self.engine = Engine()

    def start(self):
        self.engine.start()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.engine.wait_for_start(timeout)
    
    def start_single_threaded(self):
        self.engine.start_single_threaded()
    
    def wait(self):
        pass

    def stop(self):
        self.engine._controlled_stop()
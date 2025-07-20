
import configparser
import importlib
import logging
from saq.collectors.base_collector import Collector
from saq.configuration.config import get_config
from saq.constants import CONFIG_REMOTE_EMAIL_COLLECTOR
from saq.error.reporting import report_exception


class RemoteEmailCollector(Collector):
    """Base email collector class for collecting remote email.

    Sets functionality / required interface for
    collecting email."""
    def __init__(self,*args, **kwargs,) -> None:
        # Order of initialization is EmailCollector, ABC, Collector, Object.
        # This super call should skip over ABC and initialize Collector
        super().__init__(
            *args,
            service_config=get_config()[CONFIG_REMOTE_EMAIL_COLLECTOR],
            workload_type='email',
            delete_files=True,
            *args, **kwargs)
        self.email_collection_processors: list = []

    def initialize_collector(self, **kwargs) -> None:
        # XXX noooooo
        _config: configparser.ConfigParser = kwargs.get('config') or get_config()

        for section in _config.sections():
            if section.startswith('remote_email_collector_'):
                if not _config[section].getboolean('enabled', fallback=False):
                    continue

                module_name = _config[section]['module']
                try:
                    _module = importlib.import_module(module_name)
                except Exception as e:
                    logging.error(f"unable to import email account config module {module_name}: {e.__class__}, {e}")
                    report_exception()
                    continue

                class_name = _config[section]['class']
                try:
                    module_class = getattr(_module, class_name)
                except AttributeError as e:
                    logging.error(f"class {class_name} does not exist in module {module_name} in email collector"
                                  f"account config {section}")
                    report_exception()
                    continue

                email_collection_processor = module_class(self)
                email_collection_processor.load_from_config(section)
                logging.info(f"loaded email collection account configuration {section}")
                self.email_collection_processors.append(email_collection_processor)

    def extended_collection(self) -> None:
        # start a separate collection thread for each account we're collecting emails for
        logging.debug('starting email account collector')
        for processor in self.email_collection_processors:
            processor.start()

        logging.debug('waiting for email account collectors to complete')
        for collection_processor in self.email_collection_processors:
            collection_processor.wait()

    def debug_extended_collection(self) -> None:
        logging.debug('debugging email account collectors')
        for processor in self.email_collection_processors:
            processor.debug()
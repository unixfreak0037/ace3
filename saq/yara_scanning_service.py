# vim: sw=4:ts=4:et
#
# ACE service wrapper for YaraScannerServer
#

import os
import os.path

from yara_scanner import YaraScannerServer

import logging

from saq.configuration import get_config
from saq.constants import CONFIG_YARA_SCANNER
from saq.environment import get_base_dir, get_data_dir
from saq.service import ACEServiceInterface
from saq.util import abs_path, create_directory

KNOWN_ERRORS = ['no scanners available', 'unable to process client request: [Errno 32] Broken pipe']

class YSSService(ACEServiceInterface):

    def __init__(self):
        self.service_config = get_config()[CONFIG_YARA_SCANNER]
        if not os.path.isdir(self.socket_dir):
            create_directory(self.socket_dir)

        self.yss_server = YaraScannerServer(
            base_dir=get_base_dir(),
            signature_dir=self.signature_dir,
            socket_dir=self.socket_dir,
            update_frequency=self.service_config.getint('update_frequency'),
            backlog=self.service_config.getint('backlog'),
            default_timeout=self.service_config.getint('default_timeout', fallback=5),
        )

    def start(self):
        self.yss_server.start()
    
    def wait_for_start(self, timeout: float = 5) -> bool:
        return True
    
    def start_single_threaded(self):
        self.yss_server = YaraScannerServer(
            base_dir=get_base_dir(),
            signature_dir=self.signature_dir,
            socket_dir=self.socket_dir,
            update_frequency=self.service_config.getint('update_frequency'),
            backlog=self.service_config.getint('backlog'),
            default_timeout=self.service_config.getint('default_timeout', fallback=5),
        )

        try:
            self.yss_server.start()
            self.yss_server.wait()
        except Exception as e:
            if str(e) not in KNOWN_ERRORS:
                raise

            logging.warning(e)
    
    def stop(self):
        self.yss_server.stop()
    
    def wait(self):
        self.yss_server.wait()

    @property
    def socket_dir(self):
        return os.path.join(get_data_dir(), self.service_config['socket_dir'])

    @property
    def signature_dir(self):
        return abs_path(self.service_config['signature_dir'])
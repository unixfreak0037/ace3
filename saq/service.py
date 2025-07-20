import importlib
from typing import Protocol


from saq.configuration.config import get_config, get_config_value

class ACEServiceInterface(Protocol):
    def start(self):
        ...

    def wait_for_start(self, timeout: float = 5) -> bool:
        ...

    def start_single_threaded(self):
        ...

    def stop(self):
        ...

    def wait(self):
        ...

class ACEServiceAdapter(ACEServiceInterface):
    def __init__(self, service: ACEServiceInterface):
        self.service = service
        
    def start(self):
        self.service.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return self.service.wait_for_start(timeout)

    def start_single_threaded(self):
        self.service.start_single_threaded()

    def stop(self):
        self.service.stop()

    def wait(self):
        self.service.wait()
        
def load_service(_module: str, _class: str) -> ACEServiceInterface:
    module = importlib.import_module(_module)
    class_definition = getattr(module, _class)
    return ACEServiceAdapter(class_definition())

def load_service_by_name(name: str) -> ACEServiceInterface:
    for section_name in get_config().sections():
        if section_name == f"service_{name}":
            return load_service(get_config_value(section_name, "module"), get_config_value(section_name, "class"))

    raise RuntimeError(f"service {name} not found")

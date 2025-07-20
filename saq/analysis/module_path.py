import inspect
import re
from typing import Optional, Type, Union


def MODULE_PATH(module_object: Union["saq.analysis.Analysis", "saq.module.AnalysisModule", Type["saq.analysis.Analysis"], str], instance: Optional[str]=None): # pyright: ignore
    """Returns the Analysis "module_path" used as a key to look up Analysis in ACE."""
    from saq.analysis.analysis import Analysis
    from saq.modules import AnalysisModule
    from saq.modules.interfaces import AnalysisModuleInterface

    assert isinstance(module_object, Analysis) or \
           isinstance(module_object, AnalysisModule) or \
           isinstance(module_object, AnalysisModuleInterface) or \
           (inspect.isclass(module_object) and issubclass(module_object, Analysis)) or \
           isinstance(module_object, str)

    # is this already a module path?
    if isinstance(module_object, str):
        if _MODULE_PATH_REGEX.match(module_object):
            return module_object
        else:
            raise ValueError("given module path does not match regex", module_object)

    # did we pass an instance of an Analysis
    if isinstance(module_object, AnalysisModuleInterface):
        return module_object.get_module_path()
    elif isinstance(module_object, Analysis):
        instance = module_object.instance
        module_object = type(module_object)
    elif isinstance(module_object, AnalysisModule):
        instance = module_object.instance
        module_object = module_object.generated_analysis_type
    # or did we pass a class?
    elif inspect.isclass(module_object):
        instance = instance # just so it's clear

    result = '{}:{}'.format(module_object.__module__, module_object.__name__)
    if instance is not None:
        result += f':{instance}'

    return result

_MODULE_PATH_REGEX = re.compile(r'^([^:]+):([^:]+)(?::(.+))?$')
def SPLIT_MODULE_PATH(module_path: str) -> tuple[str, str, str]:
    """Given a MODULE_PATH result, return a tuple of (module, class, instance)."""
    match_result = _MODULE_PATH_REGEX.match(module_path)
    if match_result is None:
        raise ValueError("invalid module path", module_path)

    return match_result.groups()

def IS_MODULE_PATH(module_path_string: str) -> bool:
    """Returns True if the given string matches a MODULE_PATH result, False otherwise."""
    assert isinstance(module_path_string, str)
    match_result = _MODULE_PATH_REGEX.match(module_path_string)
    if not match_result:
        return False

    return True

# regex used to convert str(type(Analysis)) into a "module path"
CLASS_STRING_REGEX = re.compile(r"^<class '([^']+)'>$")
from abc import ABC
import importlib
import inspect
import logging
import pkgutil
from types import ModuleType
from typing import Type, Union


def test_module(module_name: str) -> Union[ModuleType, None]:
    """Return module if it exists."""
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError:
        return None

def harvest_modules(starting_module_name: str) -> set:
    """Return set of modules found within the module/package hierarchy."""
    module_set = set()
    if (module_obj := test_module(starting_module_name)) is not None:
        module_set.add(module_obj)
    try:
        # If it quacks like a package (it has __path__), then we'll walk it for modules like a package
        for _, name, _ in pkgutil.walk_packages(module_obj.__path__):
            # Explicitly build the module name, so that we don't accidentally
            # add modules that resolve to some package outside of our
            # current package hierarchy.
            sub_module_name = f'{starting_module_name}.{name}'
            module_set |= harvest_modules(sub_module_name)
    except AttributeError:
        # no quacks given
        pass
    return module_set


def find_classes(starting_module: str, abstract_class: Type[ABC]) -> dict:
    """Search out and add all classes that are subclasses
    of a base abstract class. You can use this to populate
    test parametrization, to ensure classes that inherit an
    abstract class are implementing the base class features
    correctly."""
    class_map = {}
    sub_modules = harvest_modules(starting_module)
    for module in sub_modules:
        for _, value in inspect.getmembers(module, predicate=inspect.isclass):
            # If it's not a subclass of the class we want to test, then we don't care
            if not issubclass(value, abstract_class):
                continue
            # We want to check actual subclasses, not the abstract class itself
            if value == abstract_class:
                continue
            class_name = value.__name__
            class_path = f'{value.__module__}.{class_name}'
            class_map[class_path] = getattr(module, class_name)
    return class_map


def _load_python_module(module_name: str, **kwargs) -> Union[ModuleType, None]:
    try:
        return kwargs.get('module') or importlib.import_module(module_name)
    except Exception as e:
        logging.error(f"unable to import module {module_name}: {e.__class__}, {e}")
        return None


def _load_python_class_from_module(imported_module: ModuleType, class_name: str) -> Union[Type, None]:
    try:
        return getattr(imported_module, class_name)
    except Exception as e:
        logging.error(f"unable to load {class_name} from module {imported_module.__name__}")
        return None


def load_python_class_from_module(module_name: str, class_name: str) -> Union[Type, None]: # pyright: ignore
    if (module := _load_python_module(module_name)) is None:
        return None
    return _load_python_class_from_module(module, class_name)
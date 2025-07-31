import os
from saq.environment import get_base_dir
from saq.integration.integration_util import get_integration_name_from_path, get_integration_path_from_name, get_integration_var_base_dir


def _create_symlink_name(integration_name: str) -> str:
    return f"test_external_integration_{integration_name}"

def _get_tests_dir() -> str:
    return os.path.join(get_base_dir(), "tests")

def install_integration(name: str) -> bool:
    dir_path = get_integration_path_from_name(name)
    if not os.path.exists(dir_path):
        return False

    source_test_dir = os.path.join(dir_path, "tests")
    if not os.path.exists(source_test_dir):
        return False

    # symlink needs to be relative to the tests directory
    relative_source_test_dir = os.path.relpath(source_test_dir, start=_get_tests_dir())

    integration_name = get_integration_name_from_path(dir_path)
    target_test_dir = os.path.join(_get_tests_dir(), _create_symlink_name(integration_name))
    if os.path.exists(target_test_dir):
        return False

    # Create a symlink to the integration directory in the tests directory
    os.symlink(relative_source_test_dir, target_test_dir)
    return True

def uninstall_integration(name: str) -> bool:
    symlink_path = os.path.join(_get_tests_dir(), _create_symlink_name(name))
    if os.path.exists(symlink_path):
        os.remove(symlink_path)
        return True

    return False

def is_integration_installed(name: str) -> bool:
    """Returns True if the integration is installed, False otherwise."""
    target_test_dir = os.path.join(_get_tests_dir(), _create_symlink_name(name))
    return os.path.exists(target_test_dir)

def _ensure_var_dir_exists(var_dir: str):
    if not os.path.exists(var_dir):
        os.makedirs(var_dir)

def _get_disabled_path(var_dir: str) -> str:
    return os.path.join(var_dir, "disabled")

def enable_integration(name: str) -> bool:
    """Enables the integration. This is done by removing the disabled file if it exists."""
    var_dir = os.path.join(get_integration_var_base_dir(), name)
    disabled_path = _get_disabled_path(var_dir)
    if os.path.exists(disabled_path):
        os.remove(disabled_path)

    return not os.path.exists(disabled_path)

def disable_integration(name: str):
    """Disables the integration. This is done by creating a disabled file in the integration's var directory."""
    var_dir = os.path.join(get_integration_var_base_dir(), name)
    _ensure_var_dir_exists(var_dir)
    disabled_path = _get_disabled_path(var_dir)
    if not os.path.exists(disabled_path):
        with open(disabled_path, "w") as _:
            pass

    return os.path.exists(disabled_path)

def is_integration_enabled(name: str) -> bool:
    """Returns True if the integration is enabled, False otherwise.
    
    Parameters
    ----------
    dir_path : str
        The path to the integration directory.
    """
    var_dir = os.path.join(get_integration_var_base_dir(), name)
    disabled_path = _get_disabled_path(var_dir)
    return not os.path.exists(disabled_path)
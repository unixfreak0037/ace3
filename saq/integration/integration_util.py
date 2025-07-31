import os

from saq.environment import get_base_dir, get_data_dir

def get_integration_base_dir() -> str:
    """Returns the absolute path to where integrations are stored."""
    return os.path.join(get_base_dir(), "integrations")

def get_integration_var_base_dir() -> str:
    """Returns the absolute path to where integration state variables are stored."""
    return os.path.join(get_data_dir(), "var", "integrations")

def get_integration_name_from_path(dir_path: str) -> str:
    """Returns the name of the integration from the directory path."""
    if not dir_path:
        raise ValueError("integration directory path is empty")
    
    if dir_path.endswith("/"):
        raise ValueError(f"integration directory path {dir_path} does not end with a slash")
    
    return os.path.basename(dir_path)

def get_integration_path_from_name(name: str) -> str:
    """Returns the path to the integration from the name."""
    return os.path.join(get_integration_base_dir(), name)
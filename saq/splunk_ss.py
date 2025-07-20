#!/usr/bin/env python3

import logging
import os
import os.path

from configparser import ConfigParser
from typing import Optional

from saq.splunk import SplunkClient, SavedSearch

def load_from_ini(file_path: str) -> Optional[SavedSearch]:
    """Reads a SavedSearch object from an ini file and returns it.
    If the ini cannot be loaded then None is returned."""
    config = ConfigParser()
    config.read(file_path)
    if "rule" not in config:
        logging.warning("%s does not contain rule section", file_path)
        return None

    rule = config["rule"]
    for key in "name", "description", "type", "search", "user", "app":
        if key not in rule:
            logging.warning("%s does not contain value for %s", file_path, key)
            return None

    logging.debug("loading saved search from %s", file_path)

    return SavedSearch(
        name=rule["name"],
        description=rule["description"],
        type=rule["type"],
        search=rule["search"],
        ns_user=rule["user"],
        ns_app=rule["app"],
    )

def load_ini_files(dir_path: str) -> list[SavedSearch]:
    """Returns a list of SavedSearch objects loaded from the ini files in the target directory."""
    result = []
    logging.debug("loading saved searches from %s", dir_path)
    for file_name in os.listdir(dir_path):
        if not file_name:
            continue

        if not file_name.endswith(".savedsearch"):
            continue

        # skip template files
        if file_name.startswith("template_"):
            continue

        file_path = os.path.join(dir_path, file_name)
        if not os.path.isfile(file_path):
            continue

        search = load_from_ini(file_path)
        if search:
            result.append(search)

    logging.debug("loaded %s saved searches from %s", len(result), dir_path)
    return result

def load_saved_searches(config_section_name: str, ns_user: str, ns_app: str):
    """Returns a list of all the saved searches currently in Splunk.
    Note that the type, ns_user and ns_app of each search result gets set here."""
    client = SplunkClient(config=config_section_name, user_context=ns_user, app=ns_app)
    searches = client.get_saved_searches()
    for search in searches:
        search.type = config_section_name
        search.ns_user = ns_user
        search.ns_app = ns_app

    return searches

def publish_saved_search(search: SavedSearch) -> bool:
    """Publishes the saved search to Splunk."""
    # these must all be set
    assert isinstance(search.type, str)
    assert isinstance(search.ns_user, str)
    assert isinstance(search.ns_app, str)

    client = SplunkClient(config=search.type, user_context=search.ns_user, app=search.ns_app)
    return client.publish_saved_search(search)

def delete_saved_search(search: SavedSearch) -> bool:
    # these must all be set
    assert isinstance(search.type, str)
    assert isinstance(search.ns_user, str)
    assert isinstance(search.ns_app, str)

    client = SplunkClient(config=search.type, user_context=search.ns_user, app=search.ns_app)
    return client.delete_saved_search(search)

def sync_saved_searches(dir_path: str, config: Optional[str]=None, ns_user: Optional[str]=None, ns_app: Optional[str]=None) -> bool:
    """Syncs Splunk to the saved searches specified in the target directory.
    All new saved searches will be created.
    All existing saved searches will be updated.
    Any *managed* saved searches that exist in Splunk that do NOT exist in the target directory will be deleted."""

    # these are the saved searches we want to have
    searches = load_ini_files(dir_path)
    logging.info("processing %s local saved searches", len(searches))

    # search for duplicate names
    dupe_search = set()
    for search in searches:
        if search.name in dupe_search:
            # requires manual remediation
            logging.error("duplicate saved search name %s", search.name)
        else:
            dupe_search.add(search.name)

    # figure out what config, ns_user and ns_app we should be working with
    target_configs = {} # key = (config, ns_user, ns_app), value = [SavedSearch]
    if config and ns_user and ns_app:
        target_configs[(config, ns_user, ns_app)] = []

    for search in searches:
        key = (search.type, search.ns_user, search.ns_app)
        if key not in target_configs:
            target_configs[key] = []

        target_configs[key].append(search)

    # iterate through all the configurations we're using
    existing_searches = []
    for (config, ns_user, ns_app), local_searches in target_configs.items():
        # create a lookup of search names for this configuration
        lookup_map = set()
        for search in local_searches:
            lookup_map.add(search.name)

        logging.info("querying config %s user %s app %s", config, ns_user, ns_app)
        remote_searches = load_saved_searches(config, ns_user, ns_app)
        for remote_search in remote_searches:
            # does this search exist locally?
            if remote_search.name not in lookup_map:
                logging.info("remote search %s not found locally", remote_search.name)
                delete_saved_search(remote_search)
                continue

        for local_search in local_searches:
            publish_saved_search(local_search)

if __name__ == "__main__":
    pass

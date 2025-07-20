import os

import pytest

from saq.splunk_ss import SavedSearch, load_from_ini, load_ini_files, sync_saved_searches

@pytest.mark.unit
def test_load_from_ini(datadir):
    search = load_from_ini(str(datadir / "rules" / "good.savedsearch"))
    assert isinstance(search, SavedSearch)
    assert search.name == "test_name"
    assert search.description == "test_description"
    assert search.type == "test_type"
    assert search.search == "test_search"
    assert search.ns_user == "test_user"
    assert search.ns_app == "test_app"

@pytest.mark.unit
def test_load_from_ini_not_exists(datadir):
    search = load_from_ini(str(datadir / "rules" / "unknown.savedsearch"))
    assert search is None

@pytest.mark.parametrize("key", [
    ("name",),
    ("description",),
    ("type",),
    ("search",),
    ("user",),
    ("app",),
])
@pytest.mark.unit
def test_load_from_ini_missing_data(key, tmpdir, datadir):
    source_path = str(datadir / "rules" / "good.savedsearch")
    target_path = str(tmpdir / "test.savedsearch")
    with open(source_path, "r") as fp_in:
        with open(target_path, "w") as fp_out:
            for line in fp_in:
                if line.startswith(key):
                    continue

                fp_out.write(line)

    search = load_from_ini(target_path)
    assert search is None

@pytest.mark.unit
def test_load_ini_files(datadir):
    searches = load_ini_files(str(datadir / "rules"))
    assert len(searches) == 1

@pytest.mark.unit
def test_load_bad_ini_files(datadir):
    searches = load_ini_files(str(datadir / "rules"))
    assert len(searches) == 1

    source_path = str(datadir / "rules" / "good.savedsearch")
    target_path = str(datadir / "rules" / "bad.savedsearch")
    with open(source_path, "r") as fp_in:
        with open(target_path, "w") as fp_out:
            for line in fp_in:
                if line.startswith("name"):
                    continue

                fp_out.write(line)

    # should still be 1
    searches = load_ini_files(str(datadir / "rules"))
    assert len(searches) == 1

@pytest.mark.unit
def test_sync_saved_searches(monkeypatch, datadir):
    _config = None
    _ns_user = None
    _ns_app = None
    _call = None
    _search = None
    _results = []

    def reset():
        pass

    def mock_load_saved_searches(config: str, ns_user: str, ns_app: str):
        nonlocal _config
        nonlocal _ns_user
        nonlocal _ns_app
        nonlocal _call
        nonlocal _results

        _config = config
        _ns_user = ns_user
        _ns_app = ns_app
        _call = mock_load_saved_searches
        return _results

    def mock_delete_saved_search(search: SavedSearch):
        nonlocal _call
        nonlocal _search

        _search = search
        _call = mock_delete_saved_search

    def mock_publish_saved_search(search: SavedSearch):
        nonlocal _call
        nonlocal _search

        _search = search
        _call = mock_publish_saved_search

    import saq.splunk_ss
    monkeypatch.setattr(saq.splunk_ss, "load_saved_searches", mock_load_saved_searches)
    monkeypatch.setattr(saq.splunk_ss, "delete_saved_search", mock_delete_saved_search)
    monkeypatch.setattr(saq.splunk_ss, "publish_saved_search", mock_publish_saved_search)

    sync_saved_searches(str(datadir / "rules"))
    assert _call == mock_publish_saved_search
    assert isinstance(_search, SavedSearch)
    assert _search.name == "test_name"

    _results = [ _search ]

    sync_saved_searches(str(datadir / "rules"))

    assert _call == mock_publish_saved_search
    assert isinstance(_search, SavedSearch)
    assert _search.name == "test_name"

    _results = [ _search ]

    os.remove(str(datadir / "rules" / "good.savedsearch"))

    sync_saved_searches(str(datadir / "rules"), "test_type", "test_user", "test_app")
    assert _call == mock_delete_saved_search
    assert isinstance
    assert _config == _results[0].type

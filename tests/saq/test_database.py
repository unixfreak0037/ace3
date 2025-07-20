import uuid
import pytest

from saq.constants import F_TEST
from saq.database import Alert, get_db_connection, get_db
from saq.analysis import RootAnalysis
from saq.database import ALERT

@pytest.mark.integration
def test_rebuild_index(tmpdir):
    storage_dir = tmpdir / "alert"
    storage_dir.mkdir()
    root = RootAnalysis(tool="test", tool_instance="test", alert_type="test", uuid=str(uuid.uuid4()), storage_dir=str(storage_dir), queue="default")
    root.initialize_storage()
    root.save()
    ALERT(root)

    alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one() # pyright: ignore
    assert alert

    def _get_tag_count(alert_id) -> int:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(*) FROM tag_mapping WHERE alert_id = %s", (alert_id,))
            return cursor.fetchone()[0] # pyright: ignore

    def _get_observable_count(alert_id) -> int:
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(*) FROM observable_mapping WHERE alert_id = %s", (alert_id,))
            return cursor.fetchone()[0] # pyright: ignore

    assert _get_tag_count(alert.id) == 0
    alert.root_analysis.add_tag("test")
    alert.rebuild_index()
    assert _get_tag_count(alert.id) == 1

    assert _get_observable_count(alert.id) == 0
    alert.root_analysis.add_observable_by_spec(F_TEST, "test")
    alert.rebuild_index()
    assert _get_observable_count(alert.id) == 1

    for index in range(100):
        alert.root_analysis.add_observable_by_spec(F_TEST, f"test_{index}")

    alert.rebuild_index()
    assert _get_observable_count(alert.id) == 101

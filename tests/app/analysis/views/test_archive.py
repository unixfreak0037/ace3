from flask import url_for
import pytest

from saq.email_archive import archive_email

@pytest.mark.integration
def test_download_archive(web_client, tmpdir):
    # unknown md5
    assert web_client.get(url_for("analysis.download_archive"), query_string={
        "md5": "unknown"
    }).status_code == 400

    email = tmpdir / "test_email"
    email.write_binary(b"test")

    archive_result = archive_email(str(email), "test_message_id", ["john@localhost"])

    assert web_client.get(url_for("analysis.download_archive"), query_string={
        "md5": archive_result.hash,
    }).status_code == 200

import logging
import os
from uuid import uuid4
from flask import g, redirect, request, send_from_directory, url_for
from flask_login import current_user, login_required
from app.blueprints import analysis
from saq.configuration.config import get_config
from saq.constants import G_TEMP_DIR
from saq.database.pool import get_db_connection
from saq.email_archive import get_archive_path_by_hash, get_email_archive_local_server_name, iter_decrypt_email
from saq.environment import get_base_dir

@analysis.route("/download_archive", methods=["GET"])
@login_required
def download_archive():
    md5_hash = request.values["md5"]
    archive_path = get_archive_path_by_hash(md5_hash)

    # does it event exist?
    if not os.path.exists(archive_path):
        return "", 400

    def generate():
        for chunk in iter_decrypt_email(archive_path):
            yield chunk

    return generate(), {"Content-Type": "application/octet-stream"}
import os
from flask import request
from flask_login import login_required
from app.blueprints import analysis
from saq.email_archive import get_archive_path_by_hash, iter_decrypt_email

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
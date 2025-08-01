from app.blueprints import main
import traceback
from flask import render_template

@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error_message=str(e)), 404

@main.app_errorhandler(500)
def internal_server_error(e):
    traceback.print_exc()
    return render_template('500.html', error_message=str(e)), 500

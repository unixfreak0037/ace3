from flask import flash, redirect, url_for
from flask_login import login_required
from app.blueprints import analysis

@analysis.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    flash("search not implemented (yet)")
    return redirect(url_for('analysis.index'))

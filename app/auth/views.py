from app.blueprints import auth

import logging

from flask import render_template, redirect, request, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user

from app.auth.forms import LoginForm, ChangePasswordForm, PASS_SPECIAL_CHARS, PASS_MIN_LENGTH
from app.models import User
from saq.database import get_db
from saq.error import report_exception

def get_remote_ipv4():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

@auth.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    user = None

    try:
        user = get_db().query(User).filter_by(username=form.username.data).one_or_none()
    except Exception as e:
        logging.warning(f"login failed: invalid username {form.username.data} from {get_remote_ipv4()}: {e}")
        report_exception()
        flash('Invalid username or password.')
        return render_template('auth/login.html', form=form)

    if user is None:
        flash('Invalid username or password.')
        return render_template('auth/login.html', form=form)

    if user is not None and user.verify_password(form.password.data):
        if not user.enabled:
            flash('User is disabled.')
            return render_template('auth/login.html', form=form)

        login_user(user, form.remember_me.data)
        
        if 'current_storage_dir' in session:
            del session['current_storage_dir']

        logging.info(f"user {user.username} logged in from {get_remote_ipv4()}")

        response = redirect(request.args.get('next') or url_for('main.index'))
        # remember the username so we can autofill the field
        response.set_cookie('username', user.username)
        return response

    flash('Invalid username or password.')
    logging.warning(f"login failed: invalid password for {form.username.data} from {get_remote_ipv4()}")
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    if 'cid' in session:
        del session['cid']

    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/login/change', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow a user to change their own password.

    Although validations appear to be missing from this function, most validations
    are being handled by the form validators in forms.py:
        - New pass and confirm pass fields matching
        - Length requirements
        - Character complexity requirements
    """

    form = ChangePasswordForm()

    template_kwargs = {
        'form': form,
        'special': PASS_SPECIAL_CHARS,
        'min_length': PASS_MIN_LENGTH,
    }

    if form.validate_on_submit():
        user = get_db().query(User).filter_by(username=current_user.username).first()

        if not user.verify_password(form.current_password.data):
            logging.warning(
                f"user failed to provide correct existing password during password reset: {current_user.username}"
            )
            flash(f"Current password is incorrect", 'error')
            return render_template('auth/change-password.html', **template_kwargs)

        # user.password has a property setter decorator that handles hashing of the password upon
        # setting the password value
        user.password = form.new_password.data

        try:
            get_db().add(user)
            get_db().commit()
        except Exception as e:
            logging.error(f"error when updating user password in database: {e.__class__} - {e}")
            flash("Error when updating password. Please contact the administrator.", 'error')
            return render_template('auth/change-password.html', **template_kwargs)
        else:
            logging.info(f"user {current_user.username} successfully changed password")
            flash('Password changed successfully. Please login with new password.', 'success')
            # Invalidate session from old password and force a login
            return redirect(url_for('auth.logout'))

    return render_template('auth/change-password.html', **template_kwargs)

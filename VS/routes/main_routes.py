from flask import Blueprint, render_template, redirect, url_for, session, send_file, request
from functools import wraps
import os

# Define a Blueprint
main_bp = Blueprint('main', __name__)

# --- User/Admin Access Control Decorators ---
def user_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('user_logged_in'):
            return redirect(url_for('auth.user_login'))
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('auth.admin_login'))
        return func(*args, **kwargs)
    return wrapper

@main_bp.route('/')
def home():
    return redirect(url_for('auth.user_login'))

@main_bp.route('/main_page')
@user_required
def main_page():
    return render_template('main_page.html')

@main_bp.route('/download/<filename>')
@user_required
def download_file(filename):
    # Note: You'll need to get OUTPUT_FOLDER from the app config
    from flask import current_app
    output_folder = current_app.config['OUTPUT_FOLDER']
    file_path = os.path.join(output_folder, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=filename)
    else:
        return "File not found.", 404
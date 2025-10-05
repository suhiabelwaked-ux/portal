"""
Template views for gradual migration to API-based frontend
This maintains existing templates while adding API integration
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.services import AuthService

main_bp = Blueprint('main', __name__)

# Existing template routes (for gradual migration)
@main_bp.route('/')
def home():
    return redirect(url_for('main.user_login'))

@main_bp.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            result, error = AuthService.authenticate_user(username, password)
            
            if result and not error:
                # Store user info in session for template-based auth
                session['user_logged_in'] = True
                session['username'] = username
                session['user_id'] = result['user']['id']
                session.permanent = True
                return redirect(url_for('main.main_page'))
            else:
                return render_template('user_login.html', error=error or 'Invalid credentials')
        else:
            return render_template('user_login.html', error='Please enter both username and password')
    
    return render_template('user_login.html')

@main_bp.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            result, error = AuthService.authenticate_admin(username, password)
            
            if result and not error:
                # Store admin info in session for template-based auth
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['user_id'] = result['user']['id']
                session.permanent = True
                return redirect(url_for('main.admin'))
            else:
                return render_template('admin_login.html', error=error or 'Invalid admin credentials')
        else:
            return render_template('admin_login.html', error='Please enter both username and password')
    
    return render_template('admin_login.html')

@main_bp.route('/main_page')
def main_page():
    # Check if user is logged in
    if not session.get('user_logged_in'):
        return redirect(url_for('main.user_login'))
    return render_template('main_page.html')

@main_bp.route('/lookup_router')
def lookup_router():
    return render_template('lookup_router.html')

@main_bp.route('/lookup_firewall')
def lookup_firewall():
    return render_template('lookup_firewall.html')

@main_bp.route('/convert_router_page')
def convert_router_page():
    message = request.args.get('message')
    download_link = request.args.get('download_link')
    return render_template('convert_router.html', message=message, download_link=download_link)

@main_bp.route('/convert_firewall_page')
def convert_firewall_page():
    message = request.args.get('message')
    download_link = request.args.get('download_link')
    return render_template('convert_firewall.html', message=message, download_link=download_link)

@main_bp.route('/admin')
def admin():
    # Check if admin is logged in
    if not session.get('admin_logged_in'):
        return redirect(url_for('main.admin_login'))
    return render_template('admin.html')

@main_bp.route('/admin/manage_users')
def manage_users():
    return render_template('manage_users.html')

@main_bp.route('/manual_review')
def manual_review():
    return render_template('manual_review.html')

@main_bp.route('/review_summary')
def review_summary():
    return render_template('review_summary.html')

@main_bp.route('/export_findings')
def export_findings():
    return render_template('export_findings.html')

@main_bp.route('/logout')
def logout():
    """Logout route for template-based authentication"""
    session.clear()
    return redirect(url_for('main.user_login'))
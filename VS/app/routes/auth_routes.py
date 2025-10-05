from flask import Blueprint, render_template, request, redirect, url_for, session
from app.services import AuthService

auth_bp = Blueprint('template_auth', __name__)

@auth_bp.route('/')
def home():
    # Check if user is already logged in and redirect appropriately
    if session.get('admin_logged_in'):
        return redirect(url_for('admin'))
    elif session.get('user_logged_in'):
        return redirect(url_for('template_main.main_page'))
    else:
        return redirect(url_for('template_auth.user_login'))

@auth_bp.route('/user_login', methods=['GET', 'POST'])
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
                return redirect(url_for('template_main.main_page'))
            else:
                return render_template('user_login.html', error=error or 'Invalid credentials')
        else:
            return render_template('user_login.html', error='Please enter both username and password')
    
    return render_template('user_login.html')

@auth_bp.route('/admin_login', methods=['GET', 'POST'])
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
                
                return redirect(url_for('admin'))
            else:
                return render_template('admin_login.html', error=error or 'Invalid admin credentials')
        else:
            return render_template('admin_login.html', error='Please enter both username and password')
    
    return render_template('admin_login.html')

@auth_bp.route('/logout')
def logout():
    """Logout route for template-based authentication"""
    session.clear()
    return redirect(url_for('template_auth.user_login'))
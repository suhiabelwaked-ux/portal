from flask import Blueprint, render_template, request, redirect, url_for, session
from database import get_db_connection

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        if not conn: return "Database connection failed.", 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
        if user_data and user_data['password_hash'] == password:
            session['user_logged_in'] = True
            session['username'] = username
            return redirect(url_for('main.main_page'))
        else:
            return render_template('user_login.html', error='Invalid credentials')
    return render_template('user_login.html')

@auth_bp.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin_2025':
            session['admin_logged_in'] = True
            return redirect(url_for('admin.admin_dashboard')) # Redirect to the new admin blueprint
        else:
            return render_template('admin_login.html', error='Invalid credentials')
    return render_template('admin_login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.user_login'))
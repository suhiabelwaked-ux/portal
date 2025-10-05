from flask import Blueprint, render_template, request, redirect, url_for
from database import get_db_connection
from routes.main_routes import admin_required # Import decorator

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
@admin_required
def admin_dashboard():
    # ... (logic from the original '/admin' route) ...
    return render_template('admin.html', router_pending=router_pending, firewall_pending=firewall_pending)

@admin_bp.route('/admin/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    # ... (logic from the original '/admin/manage_users' route) ...
    return render_template('manage_users.html', users=users, message=message)
    
# ... (create routes for manage_router_vulnerabilities and manage_firewall_vulnerabilities here) ...
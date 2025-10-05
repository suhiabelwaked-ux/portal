from flask import Blueprint, render_template, request, redirect, url_for, session
from functools import wraps

admin_bp = Blueprint('template_admin', __name__)

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('template_auth.admin_login'))
        return func(*args, **kwargs)
    return wrapper

@admin_bp.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    """Admin dashboard with pending vulnerability management"""
    message = None
    
    if request.method == 'POST':
        # Handle pending vulnerability approval/rejection
        action = request.form.get('action')
        vuln_id = request.form.get('vuln_id')
        
        if action and vuln_id:
            from app.models import PendingVulnerability, Vulnerability
            from app import db
            
            pending = PendingVulnerability.query.get(vuln_id)
            if pending:
                if action == 'approve':
                    # Move to main vulnerabilities table
                    vuln = Vulnerability(name=pending.name, severity=pending.severity)
                    db.session.add(vuln)
                    db.session.delete(pending)
                    message = f'Vulnerability "{pending.name}" approved and added.'
                elif action == 'reject':
                    db.session.delete(pending)
                    message = f'Vulnerability "{pending.name}" rejected and removed.'
                
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    message = f'Error: {str(e)}'
    
    # Get pending vulnerabilities for display
    from app.models import PendingVulnerability
    pending_vulns = PendingVulnerability.query.all()
    
    return render_template('admin.html', pending_vulns=pending_vulns, message=message)

@admin_bp.route('/admin/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    """User management interface"""
    message = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            username = request.form.get('username')
            password = request.form.get('password')
            status = request.form.get('status', 'enabled')
            is_admin = request.form.get('is_admin') == 'on'
            
            if username and password:
                from app.services import AdminService
                result, error = AdminService.create_user(username, password, status, is_admin)
                if result:
                    message = f'User "{username}" created successfully.'
                else:
                    message = f'Error creating user: {error}'
        
        elif action == 'toggle_status':
            username = request.form.get('username')
            
            if username:
                from app.models import User
                from app import db
                user = User.query.filter_by(username=username).first()
                if user:
                    # Toggle status
                    user.status = 'disabled' if user.status == 'enabled' else 'enabled'
                    try:
                        db.session.commit()
                        message = f'User "{username}" status updated to "{user.status}".'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error updating user: {str(e)}'
        
        elif action == 'change_password':
            username = request.form.get('username')
            new_password = request.form.get('new_password')
            
            if username and new_password:
                from app.models import User
                from app import db
                user = User.query.filter_by(username=username).first()
                if user:
                    user.set_password(new_password)
                    try:
                        db.session.commit()
                        message = f'Password updated for user "{username}".'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error updating password: {str(e)}'
        
        elif action == 'assign_group':
            username = request.form.get('username')
            group_id = request.form.get('group_id')
            
            if username and group_id:
                from app.models import User, Group
                from app import db
                user = User.query.filter_by(username=username).first()
                group = Group.query.get(group_id)
                
                if user and group:
                    user.add_to_group(group)
                    try:
                        db.session.commit()
                        message = f'User "{username}" added to group "{group.name}".'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error assigning group: {str(e)}'
        
        elif action == 'remove_group':
            username = request.form.get('username')
            group_id = request.form.get('group_id')
            
            if username and group_id:
                from app.models import User, Group
                from app import db
                user = User.query.filter_by(username=username).first()
                group = Group.query.get(group_id)
                
                if user and group:
                    user.remove_from_group(group)
                    try:
                        db.session.commit()
                        message = f'User "{username}" removed from group "{group.name}".'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error removing group: {str(e)}'
    
    # Get all users and groups for display
    from app.models import User, Group
    users = User.query.all()
    groups = Group.query.all()
    
    return render_template('manage_users.html', users=users, groups=groups, message=message)

@admin_bp.route('/admin/manage_router_vulnerabilities', methods=['GET', 'POST'])
@admin_required
def manage_router_vulnerabilities():
    """Router vulnerability management"""
    message = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_vulnerability':
            name = request.form.get('name')
            severity = request.form.get('severity')
            
            if name and severity:
                from app.models import Vulnerability
                from app import db
                
                vuln = Vulnerability(name=name, severity=severity)
                try:
                    db.session.add(vuln)
                    db.session.commit()
                    message = f'Vulnerability "{name}" added successfully.'
                except Exception as e:
                    db.session.rollback()
                    message = f'Error adding vulnerability: {str(e)}'
        
        elif action == 'delete_vulnerability':
            vuln_id = request.form.get('vuln_id')
            if vuln_id:
                from app.models import Vulnerability
                from app import db
                
                vuln = Vulnerability.query.get(vuln_id)
                if vuln:
                    try:
                        db.session.delete(vuln)
                        db.session.commit()
                        message = f'Vulnerability "{vuln.name}" deleted.'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error deleting vulnerability: {str(e)}'
    
    # Get all vulnerabilities for display
    from app.models import Vulnerability
    vulnerabilities = Vulnerability.query.all()
    
    return render_template('manage_router_vulnerabilities.html', vulnerabilities=vulnerabilities, message=message)

@admin_bp.route('/admin/manage_firewall_vulnerabilities', methods=['GET', 'POST'])
@admin_required
def manage_firewall_vulnerabilities():
    """Firewall vulnerability management"""
    message = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_vulnerability':
            name = request.form.get('name')
            severity = request.form.get('severity')
            
            if name and severity:
                from app.models import Vulnerability
                from app import db
                
                # For now using same table, could be separate firewall table
                vuln = Vulnerability(name=name, severity=severity)
                try:
                    db.session.add(vuln)
                    db.session.commit()
                    message = f'Firewall vulnerability "{name}" added successfully.'
                except Exception as e:
                    db.session.rollback()
                    message = f'Error adding vulnerability: {str(e)}'
        
        elif action == 'delete_vulnerability':
            vuln_id = request.form.get('vuln_id')
            if vuln_id:
                from app.models import Vulnerability
                from app import db
                
                vuln = Vulnerability.query.get(vuln_id)
                if vuln:
                    try:
                        db.session.delete(vuln)
                        db.session.commit()
                        message = f'Vulnerability "{vuln.name}" deleted.'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error deleting vulnerability: {str(e)}'
    
    # Get all vulnerabilities for display  
    from app.models import Vulnerability
    vulnerabilities = Vulnerability.query.all()
    
    return render_template('manage_firewall_vulnerabilities.html', vulnerabilities=vulnerabilities, message=message)

@admin_bp.route('/admin/setup_rbac')
@admin_required
def setup_rbac():
    """Initialize RBAC system with default groups and permissions"""
    from app.models import Group, Permission
    from app import db
    
    message = None
    try:
        # Create database tables
        db.create_all()
        
        # Create default permissions
        permissions_data = [
            # User Permissions
            ('router_lookup', 'Access Router/Switch vulnerability lookup', 'user'),
            ('firewall_lookup', 'Access Firewall vulnerability lookup', 'user'),
            ('router_conversion', 'Convert Router/Switch PDF reports', 'user'),
            ('firewall_conversion', 'Convert Firewall PDF reports', 'user'),
            ('manual_review', 'Access manual security review tools', 'user'),
            ('add_pending_vuln', 'Submit vulnerabilities for approval', 'user'),
            
            # Admin Permissions
            ('manage_users', 'Create and manage user accounts', 'admin'),
            ('manage_groups', 'Create and manage user groups', 'admin'),
            ('manage_permissions', 'Assign permissions to groups', 'admin'),
            ('manage_router_vulns', 'Manage Router/Switch vulnerability database', 'admin'),
            ('manage_firewall_vulns', 'Manage Firewall vulnerability database', 'admin'),
            ('approve_pending_vulns', 'Approve or reject pending vulnerabilities', 'admin'),
            ('view_admin_dashboard', 'Access admin dashboard', 'admin'),
            ('system_admin', 'Full system administration access', 'admin'),
        ]
        
        # Create permissions
        for name, description, category in permissions_data:
            existing = Permission.query.filter_by(name=name).first()
            if not existing:
                permission = Permission(name=name, description=description, category=category)
                db.session.add(permission)
        
        # Create default groups
        groups_data = [
            ('users', 'Standard Users', [
                'router_lookup', 'firewall_lookup', 'router_conversion', 
                'firewall_conversion', 'manual_review', 'add_pending_vuln'
            ]),
            ('admins', 'System Administrators', [
                'manage_users', 'manage_groups', 'manage_permissions',
                'manage_router_vulns', 'manage_firewall_vulns', 
                'approve_pending_vulns', 'view_admin_dashboard', 'system_admin',
                'router_lookup', 'firewall_lookup', 'router_conversion', 
                'firewall_conversion', 'manual_review', 'add_pending_vuln'
            ])
        ]
        
        for name, description, permission_names in groups_data:
            existing = Group.query.filter_by(name=name).first()
            if not existing:
                group = Group(name=name, description=description)
                db.session.add(group)
                db.session.flush()
                
                # Add permissions to group
                for perm_name in permission_names:
                    permission = Permission.query.filter_by(name=perm_name).first()
                    if permission:
                        group.add_permission(permission)
        
        # Assign existing users to groups
        users_group = Group.query.filter_by(name='users').first()
        admins_group = Group.query.filter_by(name='admins').first()
        
        if users_group and admins_group:
            from app.models import User
            # Assign admin users to admin group
            admin_users = User.query.filter_by(is_admin=True).all()
            for user in admin_users:
                if admins_group not in user.groups:
                    user.add_to_group(admins_group)
            
            # Assign regular users to users group
            regular_users = User.query.filter_by(is_admin=False).all()
            for user in regular_users:
                if users_group not in user.groups:
                    user.add_to_group(users_group)
        
        db.session.commit()
        message = "RBAC system initialized successfully with default groups and permissions!"
        
    except Exception as e:
        db.session.rollback()
        message = f"Error initializing RBAC: {str(e)}"
    
    return redirect(url_for('template_admin.manage_groups', message=message))

@admin_bp.route('/admin/manage_groups', methods=['GET', 'POST'])
@admin_required
def manage_groups():
    """Group management interface"""
    message = request.args.get('message')
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create_group':
            name = request.form.get('name')
            description = request.form.get('description', '')
            
            if name:
                from app.models import Group
                from app import db
                
                # Check if group already exists
                existing = Group.query.filter_by(name=name).first()
                if not existing:
                    group = Group(name=name, description=description)
                    try:
                        db.session.add(group)
                        db.session.commit()
                        message = f'Group "{name}" created successfully.'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error creating group: {str(e)}'
                else:
                    message = f'Group "{name}" already exists.'
        
        elif action == 'delete_group':
            group_id = request.form.get('group_id')
            if group_id:
                from app.models import Group
                from app import db
                
                group = Group.query.get(group_id)
                if group:
                    try:
                        db.session.delete(group)
                        db.session.commit()
                        message = f'Group "{group.name}" deleted successfully.'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error deleting group: {str(e)}'
        
        elif action == 'assign_permission':
            group_id = request.form.get('group_id')
            permission_id = request.form.get('permission_id')
            
            if group_id and permission_id:
                from app.models import Group, Permission
                from app import db
                
                group = Group.query.get(group_id)
                permission = Permission.query.get(permission_id)
                
                if group and permission:
                    group.add_permission(permission)
                    try:
                        db.session.commit()
                        message = f'Permission "{permission.name}" assigned to group "{group.name}".'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error assigning permission: {str(e)}'
        
        elif action == 'remove_permission':
            group_id = request.form.get('group_id')
            permission_id = request.form.get('permission_id')
            
            if group_id and permission_id:
                from app.models import Group, Permission
                from app import db
                
                group = Group.query.get(group_id)
                permission = Permission.query.get(permission_id)
                
                if group and permission:
                    group.remove_permission(permission)
                    try:
                        db.session.commit()
                        message = f'Permission "{permission.name}" removed from group "{group.name}".'
                    except Exception as e:
                        db.session.rollback()
                        message = f'Error removing permission: {str(e)}'
    
    # Get all groups and permissions for display
    from app.models import Group, Permission
    groups = Group.query.all()
    permissions = Permission.query.all()
    
    return render_template('manage_groups.html', groups=groups, permissions=permissions, message=message)
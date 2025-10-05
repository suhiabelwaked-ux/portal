#!/usr/bin/env python3
"""
RBAC Setup Script - Initialize Groups and Permissions System
"""
from app import create_app, db
from app.models import User, Group, Permission

def create_default_permissions():
    """Create default permissions for the system"""
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
    
    created_permissions = []
    for name, description, category in permissions_data:
        existing = Permission.query.filter_by(name=name).first()
        if not existing:
            permission = Permission(name=name, description=description, category=category)
            db.session.add(permission)
            created_permissions.append(name)
            print(f"✅ Created permission: {name}")
        else:
            print(f"⚠️  Permission already exists: {name}")
    
    return created_permissions

def create_default_groups():
    """Create default groups for the system"""
    groups_data = [
        ('users', 'Standard Users', [
            'router_lookup', 'firewall_lookup', 'router_conversion', 
            'firewall_conversion', 'manual_review', 'add_pending_vuln'
        ]),
        ('admins', 'System Administrators', [
            'manage_users', 'manage_groups', 'manage_permissions',
            'manage_router_vulns', 'manage_firewall_vulns', 
            'approve_pending_vulns', 'view_admin_dashboard', 'system_admin',
            # Admin also gets all user permissions
            'router_lookup', 'firewall_lookup', 'router_conversion', 
            'firewall_conversion', 'manual_review', 'add_pending_vuln'
        ])
    ]
    
    created_groups = []
    for name, description, permission_names in groups_data:
        existing = Group.query.filter_by(name=name).first()
        if not existing:
            group = Group(name=name, description=description)
            db.session.add(group)
            db.session.flush()  # Get the ID
            
            # Add permissions to group
            for perm_name in permission_names:
                permission = Permission.query.filter_by(name=perm_name).first()
                if permission:
                    group.add_permission(permission)
            
            created_groups.append(name)
            print(f"✅ Created group: {name} with {len(permission_names)} permissions")
        else:
            print(f"⚠️  Group already exists: {name}")
    
    return created_groups

def assign_users_to_groups():
    """Assign existing users to appropriate groups"""
    # Get default groups
    users_group = Group.query.filter_by(name='users').first()
    admins_group = Group.query.filter_by(name='admins').first()
    
    if not users_group or not admins_group:
        print("❌ Default groups not found. Run create_default_groups first.")
        return
    
    # Assign admin users to admin group
    admin_users = User.query.filter_by(is_admin=True).all()
    for user in admin_users:
        if admins_group not in user.groups:
            user.add_to_group(admins_group)
            print(f"✅ Added admin user '{user.username}' to admins group")
    
    # Assign regular users to users group
    regular_users = User.query.filter_by(is_admin=False).all()
    for user in regular_users:
        if users_group not in user.groups:
            user.add_to_group(users_group)
            print(f"✅ Added user '{user.username}' to users group")

def setup_rbac():
    """Main setup function"""
    print("🚀 Setting up Role-Based Access Control (RBAC)")
    print("=" * 50)
    
    # Create database tables
    print("📋 Creating database tables...")
    db.create_all()
    print("✅ Database tables created")
    
    # Create default permissions
    print("\n🔐 Creating default permissions...")
    permissions = create_default_permissions()
    
    # Create default groups
    print("\n👥 Creating default groups...")
    groups = create_default_groups()
    
    # Assign existing users to groups
    print("\n🔗 Assigning users to groups...")
    assign_users_to_groups()
    
    # Commit all changes
    try:
        db.session.commit()
        print("\n✅ RBAC setup completed successfully!")
        print(f"Created {len(permissions)} permissions")
        print(f"Created {len(groups)} groups")
        print("\n🎯 Available Groups:")
        for group in Group.query.all():
            print(f"  - {group.name}: {len(group.permissions)} permissions, {len(group.users)} users")
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error during setup: {str(e)}")
        raise

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        setup_rbac()
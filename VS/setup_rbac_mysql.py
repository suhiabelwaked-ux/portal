#!/usr/bin/env python3
"""
MySQL RBAC Setup Script
This script sets up the MySQL database with RBAC tables for the vulnerability assessment application.
"""

import os
import sys
import pymysql
from werkzeug.security import generate_password_hash

# MySQL connection settings
MYSQL_CONFIG = {
    'host': os.environ.get('MYSQL_HOST', 'localhost'),
    'port': int(os.environ.get('MYSQL_PORT', 3306)),
    'user': os.environ.get('MYSQL_USER', 'root'),
    'password': os.environ.get('MYSQL_PASSWORD', 'admin_2025'),
    'database': os.environ.get('MYSQL_DATABASE', 'vulnerability_assessment'),
    'charset': 'utf8mb4'
}

def create_database_if_not_exists():
    """Create the database if it doesn't exist"""
    try:
        config_no_db = MYSQL_CONFIG.copy()
        del config_no_db['database']
        
        connection = pymysql.connect(**config_no_db)
        cursor = connection.cursor()
        
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_CONFIG['database']} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print(f"✅ Database '{MYSQL_CONFIG['database']}' created or already exists")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False

def create_rbac_tables():
    """Create all RBAC tables"""
    try:
        connection = pymysql.connect(**MYSQL_CONFIG)
        cursor = connection.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                status VARCHAR(20) DEFAULT 'enabled',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        
        # Groups table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(80) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Permissions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(80) UNIQUE NOT NULL,
                resource VARCHAR(80) NOT NULL,
                action VARCHAR(80) NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # User-Groups many-to-many table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_groups (
                user_id INT NOT NULL,
                group_id INT NOT NULL,
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )
        """)
        
        # Group-Permissions many-to-many table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS group_permissions (
                group_id INT NOT NULL,
                permission_id INT NOT NULL,
                PRIMARY KEY (group_id, permission_id),
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
            )
        """)
        
        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name TEXT NOT NULL,
                severity VARCHAR(20) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_name (name(255))
            )
        """)
        
        # Pending vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name TEXT NOT NULL,
                severity VARCHAR(20) NOT NULL,
                search_type VARCHAR(20) NOT NULL,
                submitted_by VARCHAR(80) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_name (name(255))
            )
        """)
        
        connection.commit()
        print("✅ All RBAC tables created successfully")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False

def setup_default_groups_and_permissions():
    """Create default groups and permissions"""
    try:
        connection = pymysql.connect(**MYSQL_CONFIG)
        cursor = connection.cursor()
        
        # Create default groups
        groups = [
            ('admin', 'Full system administration access'),
            ('manager', 'User management and report oversight'),
            ('user', 'Regular user access to vulnerability assessments'),
            ('viewer', 'Read-only access to reports and data')
        ]
        
        for name, description in groups:
            cursor.execute(
                "INSERT IGNORE INTO groups (name, description) VALUES (%s, %s)",
                (name, description)
            )
        
        # Create default permissions
        permissions = [
            ('manage_users', 'admin', 'manage', 'Manage user accounts and assignments'),
            ('manage_groups', 'admin', 'manage', 'Manage groups and permissions'),
            ('view_admin_panel', 'admin', 'view', 'Access admin dashboard'),
            ('convert_reports', 'reports', 'convert', 'Convert PDF reports to Word'),
            ('manual_review', 'reports', 'review', 'Perform manual security reviews'),
            ('view_reports', 'reports', 'view', 'View generated reports'),
            ('manage_vulnerabilities', 'vulnerabilities', 'manage', 'Manage vulnerability database')
        ]
        
        for name, resource, action, description in permissions:
            cursor.execute(
                "INSERT IGNORE INTO permissions (name, resource, action, description) VALUES (%s, %s, %s, %s)",
                (name, resource, action, description)
            )
        
        connection.commit()
        
        # Assign permissions to groups
        # Admin group gets all permissions
        cursor.execute("SELECT id FROM groups WHERE name = 'admin'")
        admin_group_id = cursor.fetchone()[0]
        
        cursor.execute("SELECT id FROM permissions")
        all_permissions = cursor.fetchall()
        
        for perm in all_permissions:
            cursor.execute(
                "INSERT IGNORE INTO group_permissions (group_id, permission_id) VALUES (%s, %s)",
                (admin_group_id, perm[0])
            )
        
        # Manager group gets user management permissions
        cursor.execute("SELECT id FROM groups WHERE name = 'manager'")
        manager_group_id = cursor.fetchone()[0]
        
        manager_perms = ['view_admin_panel', 'convert_reports', 'manual_review', 'view_reports']
        for perm_name in manager_perms:
            cursor.execute("SELECT id FROM permissions WHERE name = %s", (perm_name,))
            perm_result = cursor.fetchone()
            if perm_result:
                cursor.execute(
                    "INSERT IGNORE INTO group_permissions (group_id, permission_id) VALUES (%s, %s)",
                    (manager_group_id, perm_result[0])
                )
        
        # User group gets report permissions
        cursor.execute("SELECT id FROM groups WHERE name = 'user'")
        user_group_id = cursor.fetchone()[0]
        
        user_perms = ['convert_reports', 'manual_review', 'view_reports']
        for perm_name in user_perms:
            cursor.execute("SELECT id FROM permissions WHERE name = %s", (perm_name,))
            perm_result = cursor.fetchone()
            if perm_result:
                cursor.execute(
                    "INSERT IGNORE INTO group_permissions (group_id, permission_id) VALUES (%s, %s)",
                    (user_group_id, perm_result[0])
                )
        
        # Viewer group gets view permissions only
        cursor.execute("SELECT id FROM groups WHERE name = 'viewer'")
        viewer_group_id = cursor.fetchone()[0]
        
        cursor.execute("SELECT id FROM permissions WHERE name = 'view_reports'")
        view_perm = cursor.fetchone()
        if view_perm:
            cursor.execute(
                "INSERT IGNORE INTO group_permissions (group_id, permission_id) VALUES (%s, %s)",
                (viewer_group_id, view_perm[0])
            )
        
        connection.commit()
        print("✅ Default groups and permissions configured")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"❌ Error setting up groups and permissions: {e}")
        return False

def create_default_users():
    """Create default admin and test users"""
    try:
        connection = pymysql.connect(**MYSQL_CONFIG)
        cursor = connection.cursor()
        
        # Create admin user
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", ('admin',))
        if cursor.fetchone()[0] == 0:
            admin_password_hash = generate_password_hash('admin_2025')
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin, status) VALUES (%s, %s, %s, %s)",
                ('admin', admin_password_hash, True, 'enabled')
            )
            print("✅ Admin user created (admin/admin_2025)")
        
        # Create test user
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", ('testuser',))
        if cursor.fetchone()[0] == 0:
            user_password_hash = generate_password_hash('password123')
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin, status) VALUES (%s, %s, %s, %s)",
                ('testuser', user_password_hash, False, 'enabled')
            )
            
            # Assign testuser to admin group
            cursor.execute("SELECT id FROM users WHERE username = 'testuser'")
            user_id = cursor.fetchone()[0]
            cursor.execute("SELECT id FROM groups WHERE name = 'admin'")
            group_id = cursor.fetchone()[0]
            cursor.execute(
                "INSERT INTO user_groups (user_id, group_id) VALUES (%s, %s)",
                (user_id, group_id)
            )
            print("✅ Test user created and assigned to admin group (testuser/password123)")
        
        connection.commit()
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creating users: {e}")
        return False

def test_connection():
    """Test MySQL connection and show summary"""
    try:
        connection = pymysql.connect(**MYSQL_CONFIG)
        cursor = connection.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM groups")
        group_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM permissions")
        perm_count = cursor.fetchone()[0]
        
        print(f"✅ Connection successful!")
        print(f"   📊 Users: {user_count}")
        print(f"   🔐 Groups: {group_count}")
        print(f"   🛡️  Permissions: {perm_count}")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Setting up MySQL RBAC system for Vulnerability Assessment Application")
    print(f"📍 Host: {MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}")
    print(f"🗄️  Database: {MYSQL_CONFIG['database']}")
    print(f"👤 User: {MYSQL_CONFIG['user']}")
    print("-" * 60)
    
    # Step 1: Create database
    if not create_database_if_not_exists():
        sys.exit(1)
    
    # Step 2: Create RBAC tables
    if not create_rbac_tables():
        sys.exit(1)
    
    # Step 3: Setup groups and permissions
    if not setup_default_groups_and_permissions():
        sys.exit(1)
    
    # Step 4: Create default users
    if not create_default_users():
        sys.exit(1)
    
    # Step 5: Test connection
    if test_connection():
        print("\n🎉 MySQL RBAC setup completed successfully!")
        print("\nNext steps:")
        print("1. Start your Flask application: python app.py")
        print("2. Test admin login: admin/admin_2025")
        print("3. Test user login: testuser/password123")
        print("4. Access admin panel to manage users and roles")
    else:
        print("\n❌ Setup failed. Please check your MySQL configuration.")
        sys.exit(1)
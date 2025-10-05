#!/usr/bin/env python3
"""
MySQL Database Setup Script
This script sets up the MySQL database for the vulnerability assessment application.

Before running, make sure:
1. MySQL is installed and running on your PC
2. Create a database named 'vulnerability_assessment'
3. Set your MySQL credentials in environment variables or update defaults below
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
        # Connect without specifying database first
        config_no_db = MYSQL_CONFIG.copy()
        del config_no_db['database']
        
        connection = pymysql.connect(**config_no_db)
        cursor = connection.cursor()
        
        # Create database if not exists
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_CONFIG['database']} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        print(f"✅ Database '{MYSQL_CONFIG['database']}' created or already exists")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False

def create_tables():
    """Create all necessary tables"""
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
        
        # Pending vulnerabilities table (renamed to match app expectations)
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
        
        # RBAC Tables - Groups
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS `groups` (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(80) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # RBAC Tables - Permissions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS `permissions` (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(80) UNIQUE NOT NULL,
                resource VARCHAR(80) NOT NULL,
                action VARCHAR(80) NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # RBAC Tables - User-Groups many-to-many
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_groups (
                user_id INT NOT NULL,
                group_id INT NOT NULL,
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
            )
        """)
        
        # RBAC Tables - Group-Permissions many-to-many
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS group_permissions (
                group_id INT NOT NULL,
                permission_id INT NOT NULL,
                PRIMARY KEY (group_id, permission_id),
                FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
                FOREIGN KEY (permission_id) REFERENCES `permissions`(id) ON DELETE CASCADE
            )
        """)
        
        # Review sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS review_sessions (
                id INT PRIMARY KEY AUTO_INCREMENT,
                session_key VARCHAR(100) UNIQUE NOT NULL,
                filename VARCHAR(255) NOT NULL,
                username VARCHAR(80) NOT NULL,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                session_id INT NOT NULL,
                finding_number VARCHAR(20) NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                recommendation TEXT,
                status VARCHAR(10) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES review_sessions(id) ON DELETE CASCADE
            )
        """)
        
        connection.commit()
        print("✅ All tables created successfully")
        
        # Setup default RBAC groups and permissions
        setup_rbac_defaults(cursor, connection)
        
        # Create default admin user
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", ('admin',))
        if cursor.fetchone()[0] == 0:
            admin_password_hash = generate_password_hash('admin_2025')
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin, status) VALUES (%s, %s, %s, %s)",
                ('admin', admin_password_hash, True, 'enabled')
            )
            connection.commit()
            print("✅ Default admin user created (admin/admin_2025)")
        else:
            # Update existing admin user to have admin privileges
            cursor.execute("UPDATE users SET is_admin = %s WHERE username = %s", (True, 'admin'))
            connection.commit()
            print("✅ Admin user updated with admin privileges")
        
        # Create test user suhaib
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", ('suhaib',))
        if cursor.fetchone()[0] == 0:
            user_password_hash = generate_password_hash('suhaib123')
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin, status) VALUES (%s, %s, %s, %s)",
                ('suhaib', user_password_hash, False, 'enabled')
            )
            connection.commit()
            print("✅ Test user created (suhaib/suhaib123)")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False

def setup_rbac_defaults(cursor, connection):
    """Setup default RBAC groups and permissions"""
    try:
        # Create default groups
        groups = [
            ('admin', 'Full system administration access'),
            ('manager', 'User management and report oversight'),
            ('user', 'Regular user access to vulnerability assessments'),
            ('viewer', 'Read-only access to reports and data')
        ]
        
        for name, description in groups:
            cursor.execute(
                "INSERT IGNORE INTO `groups` (name, description) VALUES (%s, %s)",
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
                "INSERT IGNORE INTO `permissions` (name, resource, action, description) VALUES (%s, %s, %s, %s)",
                (name, resource, action, description)
            )
        
        connection.commit()
        
        # Assign permissions to groups
        # Admin group gets all permissions
        cursor.execute("SELECT id FROM `groups` WHERE name = 'admin'")
        admin_result = cursor.fetchone()
        if admin_result:
            admin_group_id = admin_result[0]
            cursor.execute("SELECT id FROM `permissions`")
            all_permissions = cursor.fetchall()
            
            for perm in all_permissions:
                cursor.execute(
                    "INSERT IGNORE INTO group_permissions (group_id, permission_id) VALUES (%s, %s)",
                    (admin_group_id, perm[0])
                )
        
        connection.commit()
        print("✅ RBAC groups and permissions configured")
        
    except Exception as e:
        print(f"⚠️  RBAC setup warning: {e}")

def migrate_sqlite_data():
    """Migrate data from SQLite to MySQL (if SQLite files exist)"""
    try:
        import sqlite3
        
        # Check if SQLite files exist
        sqlite_files = {
            'vulnerabilities.db': 'vulnerabilities',
            'pending_vulnerabilities.db': 'pending'
        }
        
        mysql_conn = pymysql.connect(**MYSQL_CONFIG)
        mysql_cursor = mysql_conn.cursor()
        
        for sqlite_file, table_type in sqlite_files.items():
            if os.path.exists(sqlite_file):
                print(f"📦 Migrating data from {sqlite_file}...")
                
                sqlite_conn = sqlite3.connect(sqlite_file)
                sqlite_conn.row_factory = sqlite3.Row
                sqlite_cursor = sqlite_conn.cursor()
                
                if table_type == 'vulnerabilities':
                    # Migrate main vulnerabilities
                    sqlite_cursor.execute("SELECT name, severity FROM vulnerabilities")
                    rows = sqlite_cursor.fetchall()
                    for row in rows:
                        mysql_cursor.execute(
                            "INSERT IGNORE INTO vulnerabilities (name, severity) VALUES (%s, %s)",
                            (row['name'], row['severity'])
                        )
                    print(f"   ✅ Migrated {len(rows)} vulnerabilities")
                
                elif table_type == 'pending':
                    # Migrate pending vulnerabilities
                    sqlite_cursor.execute("SELECT name, severity, search_type, submitted_by FROM pending")
                    rows = sqlite_cursor.fetchall()
                    for row in rows:
                        mysql_cursor.execute(
                            "INSERT IGNORE INTO pending (name, severity, search_type, submitted_by) VALUES (%s, %s, %s, %s)",
                            (row['name'], row['severity'], row.get('search_type', 'router'), row.get('submitted_by', 'unknown'))
                        )
                    print(f"   ✅ Migrated {len(rows)} pending vulnerabilities")
                
                sqlite_conn.close()
        
        mysql_conn.commit()
        mysql_cursor.close()
        mysql_conn.close()
        print("✅ Data migration completed")
        
    except Exception as e:
        print(f"⚠️  Data migration skipped: {e}")

def test_connection():
    """Test MySQL connection"""
    try:
        connection = pymysql.connect(**MYSQL_CONFIG)
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        print(f"✅ Connection successful! Found {count} users in database")
        cursor.close()
        connection.close()
        return True
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Setting up MySQL database for Vulnerability Assessment Application")
    print(f"📍 Host: {MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}")
    print(f"🗄️  Database: {MYSQL_CONFIG['database']}")
    print(f"👤 User: {MYSQL_CONFIG['user']}")
    print("-" * 60)
    
    # Step 1: Create database
    if not create_database_if_not_exists():
        sys.exit(1)
    
    # Step 2: Create tables
    if not create_tables():
        sys.exit(1)
    
    # Step 3: Migrate SQLite data
    migrate_sqlite_data()
    
    # Step 4: Test connection
    if test_connection():
        print("\n🎉 MySQL setup completed successfully!")
        print("\nNext steps:")
        print("1. Update your environment variables:")
        print(f"   export MYSQL_HOST='{MYSQL_CONFIG['host']}'")
        print(f"   export MYSQL_USER='{MYSQL_CONFIG['user']}'")
        print(f"   export MYSQL_PASSWORD='{MYSQL_CONFIG['password']}'")
        print(f"   export MYSQL_DATABASE='{MYSQL_CONFIG['database']}'")
        print("\n2. Start your Flask application")
        print("3. Test login with: suhaib/suhaib123 or admin/admin_2025")
    else:
        print("\n❌ Setup failed. Please check your MySQL configuration.")
        sys.exit(1)
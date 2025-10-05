#!/usr/bin/env python3
"""
Test Admin User Authentication
This script tests if the admin user can authenticate properly.
"""

import os
import pymysql
from werkzeug.security import check_password_hash

# MySQL connection settings (same as your app)
MYSQL_CONFIG = {
    'host': os.environ.get('MYSQL_HOST', 'localhost'),
    'port': int(os.environ.get('MYSQL_PORT', 3306)),
    'user': os.environ.get('MYSQL_USER', 'root'),
    'password': os.environ.get('MYSQL_PASSWORD', 'admin_2025'),
    'database': os.environ.get('MYSQL_DATABASE', 'vulnerability_assessment'),
    'charset': 'utf8mb4'
}

def test_admin_login():
    """Test admin user authentication"""
    try:
        # Connect to database
        connection = pymysql.connect(**MYSQL_CONFIG)
        cursor = connection.cursor()
        
        # Check if admin user exists and get details
        cursor.execute("""
            SELECT id, username, password_hash, is_admin, status 
            FROM users 
            WHERE username = %s
        """, ('admin',))
        
        result = cursor.fetchone()
        
        if not result:
            print("❌ Admin user not found in database")
            return False
            
        user_id, username, password_hash, is_admin, status = result
        
        print(f"✅ Found admin user:")
        print(f"   ID: {user_id}")
        print(f"   Username: {username}")
        print(f"   Is Admin: {is_admin}")
        print(f"   Status: {status}")
        
        # Test password verification
        if check_password_hash(password_hash, 'admin_2025'):
            print("✅ Password verification: SUCCESS")
        else:
            print("❌ Password verification: FAILED")
            return False
            
        # Check admin privileges
        if is_admin:
            print("✅ Admin privileges: ENABLED")
        else:
            print("❌ Admin privileges: DISABLED")
            return False
            
        # Check status
        if status == 'enabled':
            print("✅ Account status: ENABLED")
        else:
            print(f"❌ Account status: {status}")
            return False
            
        cursor.close()
        connection.close()
        
        print("\n🎉 Admin user is properly configured!")
        print("Admin login should work with: admin / admin_2025")
        return True
        
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Testing Admin User Authentication")
    print(f"📍 Database: {MYSQL_CONFIG['host']}:{MYSQL_CONFIG['port']}/{MYSQL_CONFIG['database']}")
    print("-" * 50)
    
    if test_admin_login():
        print("\n✅ Test PASSED - Admin authentication should work")
    else:
        print("\n❌ Test FAILED - Check the issues above")
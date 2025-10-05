#!/usr/bin/env python3
"""
Modern API-based Flask Application
Vulnerability Assessment Tool with MySQL Backend

This replaces the monolithic app.py with a clean MVC architecture:
- Models: SQLAlchemy ORM with MySQL
- Views: API endpoints returning JSON
- Controllers: Service layer for business logic

Run setup_mysql.py first to initialize the database.
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app import create_app, db

# Create the Flask application
app = create_app()

def init_database():
    """Initialize database tables"""
    with app.app_context():
        try:
            # Import all models to ensure they're registered
            from app.models import User, Vulnerability, PendingVulnerability, ReviewSession, Finding
            from app.services import AdminService
            
            # Create all tables
            db.create_all()
            print("✅ Database tables created/verified")
            
            # Test connection
            result = db.session.execute(db.text('SELECT 1')).fetchone()
            if result:
                print("✅ Database connection successful")
            else:
                print("❌ Database connection failed")
                return
                
            # Bootstrap admin user if none exists
            admin_users = User.query.filter_by(is_admin=True).count()
            if admin_users == 0:
                admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
                admin_password = os.environ.get('ADMIN_PASSWORD', 'admin_secure_2025')
                
                admin_user, error = AdminService.create_user(
                    username=admin_username,
                    password=admin_password,
                    status='enabled',
                    is_admin=True
                )
                
                if admin_user:
                    print(f"🔐 Bootstrap admin created: {admin_username}")
                else:
                    print(f"❌ Failed to create admin: {error}")
                
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            print("💡 Make sure to run: python setup_mysql.py")

if __name__ == '__main__':
    print("🚀 Starting Modern Vulnerability Assessment API")
    print("=" * 50)
    
    # Initialize database
    init_database()
    
    # Create upload/output directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('output', exist_ok=True)
    os.makedirs('temp_data', exist_ok=True)
    
    print("\n📡 API Endpoints Available:")
    print("Authentication:")
    print("  POST /api/auth/login - User login")
    print("  POST /api/auth/admin/login - Admin login")
    print("  GET  /api/auth/me - Current user info")
    print("\nVulnerabilities:")
    print("  POST /api/vulns/lookup - Lookup vulnerability")
    print("  POST /api/vulns/pending - Add pending vulnerability")
    print("  GET  /api/vulns/ - Get all vulnerabilities")
    print("\nFile Processing:")
    print("  POST /api/files/convert/router - Convert router PDF")
    print("  POST /api/files/convert/firewall - Convert firewall PDF")
    print("  GET  /api/files/download/<filename> - Download file")
    print("\nAdmin (requires admin token):")
    print("  GET  /api/admin/users - Manage users")
    print("  POST /api/admin/users - Create user")
    print("  POST /api/admin/pending/<id>/approve - Approve vulnerability")
    print("\nReview System:")
    print("  POST /api/review/sessions - Create review session")
    print("  GET  /api/review/sessions/<key>/summary - Get summary")
    print("  PATCH /api/review/sessions/<key>/findings/<id> - Update finding")
    
    print("\n🌐 Frontend Templates (gradual migration):")
    print("  GET  / - User login page")
    print("  GET  /main_page - Main dashboard")
    print("  GET  /admin - Admin dashboard")
    
    database_url = os.environ.get('DATABASE_URL', '')
    database_type = "PostgreSQL" if "postgres" in database_url else "MySQL"
    print(f"\n🗄️  Database: {database_type}")
    print(f"🔧 Environment: {'Production' if not app.debug else 'Development'}")
    print("=" * 50)
    
    # Run the application with secure debug setting
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(
        host='0.0.0.0', 
        port=5000, 
        debug=debug_mode
    )
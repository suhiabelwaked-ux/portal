from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import os

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
ma = Marshmallow()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # Configuration - Secure defaults required
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        if not is_debug:
            raise ValueError('SECRET_KEY environment variable is required in production')
        app.config['SECRET_KEY'] = 'dev-only-vulnerability-assessment-app-2025-key'
        
    # Database configuration - MySQL only
    database_url = os.environ.get('DATABASE_URL')
    if database_url and 'mysql' in database_url:
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print(f"📍 Using DATABASE_URL: MySQL database")
    else:
        # Default MySQL configuration
        mysql_host = os.environ.get('MYSQL_HOST', 'localhost')
        mysql_user = os.environ.get('MYSQL_USER', 'root')
        mysql_password = os.environ.get('MYSQL_PASSWORD', 'admin_2025')
        mysql_database = os.environ.get('MYSQL_DATABASE', 'vulnerability_assessment')
        mysql_port = os.environ.get('MYSQL_PORT', '3306')
        
        app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}'
        print(f"📍 Using MySQL: {mysql_host}:{mysql_port}/{mysql_database}")
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    jwt_secret = os.environ.get('JWT_SECRET_KEY')
    if not jwt_secret:
        if not is_debug:
            raise ValueError('JWT_SECRET_KEY environment variable is required in production')
        jwt_secret = 'dev-only-jwt-secret-key-2025'
    app.config['JWT_SECRET_KEY'] = jwt_secret
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour
    
    # Security settings
    app.config['DEBUG'] = is_debug
    
    # Fix session cookies for iframe/cross-site usage (Replit environment)
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False  # False for development HTTP
    app.config['SESSION_COOKIE_NAME'] = 'va_session'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_PERMANENT'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
    
    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    ma.init_app(app)
    csrf.init_app(app)
    CORS(app, origins=['http://localhost:5000', 'http://127.0.0.1:5000'])
    
    # Register API blueprints (exempt from CSRF for API endpoints)
    from app.api.auth import auth_bp
    from app.api.vulnerabilities import vulns_bp
    from app.api.admin import admin_bp
    from app.api.files import files_bp
    from app.api.review import review_bp
    
    # Exempt API blueprints from CSRF protection
    csrf.exempt(auth_bp)
    csrf.exempt(vulns_bp)
    csrf.exempt(admin_bp)
    csrf.exempt(files_bp)
    csrf.exempt(review_bp)
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(vulns_bp, url_prefix='/api/vulns')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(files_bp, url_prefix='/api/files')
    app.register_blueprint(review_bp, url_prefix='/api/review')
    
    # Register template route blueprints (exempt from CSRF)
    from app.routes.auth_routes import auth_bp as template_auth_bp
    from app.routes.admin_routes import admin_bp as template_admin_bp
    from app.routes.main_routes import main_bp as template_main_bp
    
    # Exempt template blueprints from CSRF protection
    csrf.exempt(template_auth_bp)
    csrf.exempt(template_admin_bp)
    csrf.exempt(template_main_bp)
    
    app.register_blueprint(template_auth_bp)
    app.register_blueprint(template_admin_bp)
    app.register_blueprint(template_main_bp)
    
    # Enable proxy support for proper headers in Replit environment
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    return app
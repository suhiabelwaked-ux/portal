from app import db
from app.models import User
from flask_jwt_extended import create_access_token, create_refresh_token
from werkzeug.security import check_password_hash

class AuthService:
    @staticmethod
    def authenticate_user(username, password):
        """Authenticate user and return tokens if successful"""
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return None, "Invalid credentials"
            
        if user.status != 'enabled':
            return None, "Account is disabled. Please contact administrator."
            
        if not user.check_password(password):
            return None, "Invalid credentials"
            
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }, None
    
    @staticmethod
    def authenticate_admin(username, password):
        """Authenticate admin user - requires database admin account"""
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return None, "Invalid admin credentials"
            
        if user.status != 'enabled':
            return None, "Admin account is disabled"
            
        if not user.is_admin:
            return None, "Access denied - admin privileges required"
            
        if not user.check_password(password):
            return None, "Invalid admin credentials"
            
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }, None
    
    @staticmethod
    def get_user_by_id(user_id):
        """Get user by ID"""
        return User.query.get(user_id)
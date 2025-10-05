from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='enabled')  # enabled/disabled
    is_admin = db.Column(db.Boolean, default=False)  # Admin privileges
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Import at module level to avoid circular imports - this will be resolved at runtime
    groups = db.relationship('Group', secondary='user_groups', back_populates='users')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'status': self.status,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'groups': [group.name for group in self.groups] if hasattr(self, 'groups') else []
        }
    
    def has_permission(self, permission_name):
        """Check if user has a specific permission through their groups"""
        # Admin users have all permissions
        if self.is_admin:
            return True
        
        # Check if user is in any group that has this permission
        for group in self.groups:
            if group.has_permission(permission_name):
                return True
        return False
    
    def get_permissions(self):
        """Get all permissions for this user"""
        permissions = set()
        for group in self.groups:
            for permission in group.permissions:
                permissions.add(permission.name)
        return list(permissions)
    
    def add_to_group(self, group):
        """Add user to a group"""
        if group not in self.groups:
            self.groups.append(group)
    
    def remove_from_group(self, group):
        """Remove user from a group"""
        if group in self.groups:
            self.groups.remove(group)
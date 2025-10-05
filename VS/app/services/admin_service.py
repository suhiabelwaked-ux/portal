from app import db
from app.models import User, PendingVulnerability, Vulnerability
from werkzeug.security import generate_password_hash

class AdminService:
    @staticmethod
    def get_all_users():
        """Get all users"""
        users = User.query.all()
        return [user.to_dict() for user in users]
    
    @staticmethod
    def create_user(username, password, status='enabled', is_admin=False):
        """Create a new user"""
        try:
            # Check if user already exists
            existing = User.query.filter_by(username=username).first()
            if existing:
                return None, f"User '{username}' already exists"
            
            user = User(
                username=username,
                status=status,
                is_admin=is_admin
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            return user.to_dict(), None
            
        except Exception as e:
            db.session.rollback()
            return None, f"Error creating user: {str(e)}"
    
    @staticmethod
    def update_user(user_id, **kwargs):
        """Update user details"""
        try:
            user = User.query.get(user_id)
            if not user:
                return None, "User not found"
            
            if 'status' in kwargs:
                user.status = kwargs['status']
            
            if 'password' in kwargs:
                user.set_password(kwargs['password'])
                
            if 'is_admin' in kwargs:
                user.is_admin = kwargs['is_admin']
            
            db.session.commit()
            return user.to_dict(), None
            
        except Exception as e:
            db.session.rollback()
            return None, f"Error updating user: {str(e)}"
    
    @staticmethod
    def delete_user(user_id):
        """Delete a user"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False, "User not found"
            
            db.session.delete(user)
            db.session.commit()
            return True, None
            
        except Exception as e:
            db.session.rollback()
            return False, f"Error deleting user: {str(e)}"
    
    @staticmethod
    def approve_pending_vulnerability(pending_id):
        """Approve a pending vulnerability and move to main table"""
        try:
            pending = PendingVulnerability.query.get(pending_id)
            if not pending:
                return None, "Pending vulnerability not found"
            
            # Create in main vulnerability table
            vulnerability = Vulnerability(
                name=pending.name,
                severity=pending.severity
            )
            
            db.session.add(vulnerability)
            db.session.delete(pending)
            db.session.commit()
            
            return vulnerability.to_dict(), None
            
        except Exception as e:
            db.session.rollback()
            return None, f"Error approving vulnerability: {str(e)}"
    
    @staticmethod
    def reject_pending_vulnerability(pending_id):
        """Reject and delete a pending vulnerability"""
        try:
            pending = PendingVulnerability.query.get(pending_id)
            if not pending:
                return False, "Pending vulnerability not found"
            
            db.session.delete(pending)
            db.session.commit()
            return True, None
            
        except Exception as e:
            db.session.rollback()
            return False, f"Error rejecting vulnerability: {str(e)}"
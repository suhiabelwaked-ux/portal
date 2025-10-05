from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from marshmallow import ValidationError
from app.services import AdminService, AuthService
from app.schemas import CreateUserSchema, UpdateUserSchema, UserSchema

admin_bp = Blueprint('admin', __name__)

def require_admin():
    """Decorator to require admin privileges"""
    user_id = get_jwt_identity()
    user = AuthService.get_user_by_id(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 401
    
    if not getattr(user, 'is_admin', False):
        return jsonify({'error': 'Admin privileges required'}), 403
    
    return None

@admin_bp.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """Get all users (admin only)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        users = AdminService.get_all_users()
        return jsonify({
            'success': True,
            'users': users
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users', methods=['POST'])
@jwt_required()
def create_user():
    """Create a new user (admin only)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        schema = CreateUserSchema()
        data = schema.load(request.json)
        
        result, error = AdminService.create_user(
            data['username'],
            data['password'],
            data.get('status', 'enabled'),
            data.get('is_admin', False)
        )
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'user': result
        }), 201
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users/<int:user_id>', methods=['PATCH'])
@jwt_required()
def update_user(user_id):
    """Update user (admin only)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        schema = UpdateUserSchema()
        data = schema.load(request.json)
        
        result, error = AdminService.update_user(user_id, **data)
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'user': result
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Delete user (admin only)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        success, error = AdminService.delete_user(user_id)
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/pending/<int:pending_id>/approve', methods=['POST'])
@jwt_required()
def approve_pending_vulnerability(pending_id):
    """Approve a pending vulnerability (admin only)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        result, error = AdminService.approve_pending_vulnerability(pending_id)
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'vulnerability': result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/pending/<int:pending_id>/reject', methods=['DELETE'])
@jwt_required()
def reject_pending_vulnerability(pending_id):
    """Reject a pending vulnerability (admin only)"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        success, error = AdminService.reject_pending_vulnerability(pending_id)
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'message': 'Pending vulnerability rejected'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
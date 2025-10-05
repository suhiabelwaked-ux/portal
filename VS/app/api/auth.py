from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from marshmallow import ValidationError
from app.services import AuthService
from app.schemas import LoginSchema, UserSchema

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        schema = LoginSchema()
        data = schema.load(request.json)
        
        result, error = AuthService.authenticate_user(
            data['username'], 
            data['password']
        )
        
        if error:
            return jsonify({'error': error}), 401
        
        return jsonify({
            'success': True,
            'access_token': result['access_token'],
            'refresh_token': result['refresh_token'],
            'user': result['user']
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/admin/login', methods=['POST'])
def admin_login():
    """Admin login endpoint"""
    try:
        schema = LoginSchema()
        data = schema.load(request.json)
        
        result, error = AuthService.authenticate_admin(
            data['username'], 
            data['password']
        )
        
        if error:
            return jsonify({'error': error}), 401
        
        return jsonify({
            'success': True,
            'access_token': result['access_token'],
            'refresh_token': result['refresh_token'],
            'user': result['user']
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    try:
        user_id = get_jwt_identity()
        user = AuthService.get_user_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user.to_dict() if hasattr(user, 'to_dict') else user})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout endpoint (optional - JWT tokens expire naturally)"""
    return jsonify({'message': 'Logged out successfully'})
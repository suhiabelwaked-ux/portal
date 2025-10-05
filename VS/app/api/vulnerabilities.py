from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from marshmallow import ValidationError
from app.services import VulnerabilityService
from app.schemas import VulnerabilityLookupSchema, CreatePendingVulnerabilitySchema

vulns_bp = Blueprint('vulnerabilities', __name__)

@vulns_bp.route('/lookup', methods=['POST'])
@jwt_required()
def lookup_vulnerability():
    """Look up vulnerability by name"""
    try:
        schema = VulnerabilityLookupSchema()
        data = schema.load(request.json)
        
        search_type = request.json.get('search_type', 'router')
        result = VulnerabilityService.lookup_vulnerability(
            data['name'], 
            search_type
        )
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulns_bp.route('/router/lookup', methods=['POST'])
@jwt_required()
def lookup_router_vulnerability():
    """Look up router vulnerability by name"""
    try:
        schema = VulnerabilityLookupSchema()
        data = schema.load(request.json)
        
        result = VulnerabilityService.lookup_vulnerability(data['name'], 'router')
        return jsonify({
            'success': True,
            'result': result
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulns_bp.route('/firewall/lookup', methods=['POST'])
@jwt_required()
def lookup_firewall_vulnerability():
    """Look up firewall vulnerability by name"""
    try:
        schema = VulnerabilityLookupSchema()
        data = schema.load(request.json)
        
        result = VulnerabilityService.lookup_vulnerability(data['name'], 'firewall')
        return jsonify({
            'success': True,
            'result': result
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulns_bp.route('/pending', methods=['POST'])
@jwt_required()
def add_pending_vulnerability():
    """Add a new pending vulnerability"""
    try:
        user_id = get_jwt_identity()
        user = VulnerabilityService.get_user_by_id(user_id)  # We'll need to add this method
        username = user.username if hasattr(user, 'username') else str(user_id)
        
        schema = CreatePendingVulnerabilitySchema()
        data = schema.load(request.json)
        
        result, error = VulnerabilityService.add_pending_vulnerability(
            data['name'],
            data['severity'],
            data['search_type'],
            username
        )
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'vulnerability': result
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulns_bp.route('/', methods=['GET'])
@jwt_required()
def get_all_vulnerabilities():
    """Get all approved vulnerabilities"""
    try:
        vulnerabilities = VulnerabilityService.get_all_vulnerabilities()
        return jsonify({
            'success': True,
            'vulnerabilities': vulnerabilities
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulns_bp.route('/pending', methods=['GET'])
@jwt_required()
def get_pending_vulnerabilities():
    """Get all pending vulnerabilities"""
    try:
        pending = VulnerabilityService.get_pending_vulnerabilities()
        return jsonify({
            'success': True,
            'pending_vulnerabilities': pending
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
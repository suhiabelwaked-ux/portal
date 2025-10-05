from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from marshmallow import ValidationError
from app.services import ReviewService
from app.schemas import CreateReviewSessionSchema, UpdateFindingSchema
import json

review_bp = Blueprint('review', __name__)

@review_bp.route('/sessions', methods=['POST'])
@jwt_required()
def create_review_session():
    """Create a new review session from uploaded PDF"""
    try:
        user_id = get_jwt_identity()
        
        # Get findings data from request (would be extracted from PDF processing)
        findings_data = request.json.get('findings', [])
        filename = request.json.get('filename', 'manual_review.pdf')
        
        result, error = ReviewService.create_review_session(
            filename,
            str(user_id),
            findings_data
        )
        
        if error:
            return jsonify({'error': error}), 500
        
        return jsonify({
            'success': True,
            'session': result
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@review_bp.route('/sessions/<session_key>', methods=['GET'])
@jwt_required()
def get_review_session(session_key):
    """Get review session details"""
    try:
        session = ReviewService.get_session_by_key(session_key)
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        return jsonify({
            'success': True,
            'session': session
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@review_bp.route('/sessions/<session_key>/findings', methods=['GET'])
@jwt_required()
def get_session_findings(session_key):
    """Get all findings for a session"""
    try:
        findings, error = ReviewService.get_session_findings(session_key)
        if error:
            return jsonify({'error': error}), 404
        
        return jsonify({
            'success': True,
            'findings': findings
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@review_bp.route('/sessions/<session_key>/findings/<int:finding_id>', methods=['PATCH'])
@jwt_required()
def update_finding_status(session_key, finding_id):
    """Update the status of a specific finding"""
    try:
        schema = UpdateFindingSchema()
        data = schema.load(request.json)
        
        result, error = ReviewService.update_finding_status(
            session_key,
            finding_id,
            data['status']
        )
        
        if error:
            return jsonify({'error': error}), 400
        
        return jsonify({
            'success': True,
            'finding': result
        })
        
    except ValidationError as e:
        return jsonify({'error': 'Invalid input', 'details': e.messages}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@review_bp.route('/sessions/<session_key>/summary', methods=['GET'])
@jwt_required()
def get_session_summary(session_key):
    """Get summary of session findings"""
    try:
        summary, error = ReviewService.get_session_summary(session_key)
        if error:
            return jsonify({'error': error}), 404
        
        return jsonify({
            'success': True,
            'summary': summary
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@review_bp.route('/sessions/<session_key>/failed', methods=['GET'])
@jwt_required()
def get_failed_findings(session_key):
    """Get only failed findings for a session"""
    try:
        failed_findings, error = ReviewService.get_failed_findings(session_key)
        if error:
            return jsonify({'error': error}), 404
        
        return jsonify({
            'success': True,
            'failed_findings': failed_findings
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
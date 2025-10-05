from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required
from werkzeug.utils import secure_filename
from app.services import FileService
import os

files_bp = Blueprint('files', __name__)

@files_bp.route('/convert/router', methods=['POST'])
@jwt_required()
def convert_router():
    """Convert router PDF to DOCX"""
    try:
        if 'pdf_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['pdf_file']
        if not file or not file.filename:
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file
        file_path, error = FileService.save_uploaded_file(file)
        if error:
            return jsonify({'error': error}), 400
        
        # Convert file
        output_filename, error = FileService.convert_router_pdf(file_path)
        if error:
            FileService.cleanup_temp_files([file_path])
            return jsonify({'error': error}), 500
        
        # Clean up uploaded file
        FileService.cleanup_temp_files([file_path])
        
        return jsonify({
            'success': True,
            'message': 'Router/Switch report converted successfully!',
            'download_url': f'/api/files/download/{output_filename}',
            'filename': output_filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/convert/firewall', methods=['POST'])
@jwt_required()
def convert_firewall():
    """Convert firewall PDF to DOCX"""
    try:
        if 'pdf_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['pdf_file']
        if not file or not file.filename:
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file
        file_path, error = FileService.save_uploaded_file(file)
        if error:
            return jsonify({'error': error}), 400
        
        # Convert file
        output_filename, error = FileService.convert_firewall_pdf(file_path)
        if error:
            FileService.cleanup_temp_files([file_path])
            return jsonify({'error': error}), 500
        
        # Clean up uploaded file
        FileService.cleanup_temp_files([file_path])
        
        return jsonify({
            'success': True,
            'message': 'Firewall report converted successfully!',
            'download_url': f'/api/files/download/{output_filename}',
            'filename': output_filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/download/<filename>', methods=['GET'])
@jwt_required()
def download_file(filename):
    """Download converted file"""
    try:
        file_path = FileService.get_download_path(filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(
            file_path, 
            as_attachment=True, 
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
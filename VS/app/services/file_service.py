import os
import uuid
from werkzeug.utils import secure_filename
from flask import current_app
import TestwithSeverity
import FWADPTE

class FileService:
    @staticmethod
    def save_uploaded_file(file, file_type='pdf'):
        """Save uploaded file and return file path"""
        if not file or not file.filename:
            return None, "No file provided"
        
        if not file.filename.endswith('.pdf'):
            return None, "Only PDF files are allowed"
        
        try:
            filename = secure_filename(file.filename or 'upload.pdf')
            # Add unique identifier to prevent conflicts
            unique_filename = f"{uuid.uuid4()}_{filename}"
            
            upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            
            file_path = os.path.join(upload_folder, unique_filename)
            file.save(file_path)
            
            return file_path, None
            
        except Exception as e:
            return None, f"Error saving file: {str(e)}"
    
    @staticmethod
    def convert_router_pdf(pdf_path):
        """Convert router PDF to DOCX using TestwithSeverity"""
        try:
            output_folder = current_app.config.get('OUTPUT_FOLDER', 'output')
            os.makedirs(output_folder, exist_ok=True)
            
            # Generate output filename
            filename = os.path.basename(pdf_path)
            output_filename = os.path.splitext(filename)[0] + '_router.docx'
            output_path = os.path.join(output_folder, output_filename)
            
            # Perform conversion
            success = TestwithSeverity.extract_and_style_audit_findings(pdf_path, output_path)
            
            if success:
                return output_filename, None
            else:
                return None, "Conversion failed"
                
        except Exception as e:
            return None, f"Error converting router PDF: {str(e)}"
    
    @staticmethod
    def convert_firewall_pdf(pdf_path):
        """Convert firewall PDF to DOCX using FWADPTE"""
        try:
            output_folder = current_app.config.get('OUTPUT_FOLDER', 'output')
            os.makedirs(output_folder, exist_ok=True)
            
            # Generate output filename
            filename = os.path.basename(pdf_path)
            output_filename = os.path.splitext(filename)[0] + '_firewall.docx'
            output_path = os.path.join(output_folder, output_filename)
            
            # Perform conversion
            generator = FWADPTE.ReportGenerator(pdf_path, output_path)
            success = generator.run()
            
            if success:
                return output_filename, None
            else:
                return None, "Conversion failed"
                
        except Exception as e:
            return None, f"Error converting firewall PDF: {str(e)}"
    
    @staticmethod
    def get_download_path(filename):
        """Get the full path for downloading a file"""
        output_folder = current_app.config.get('OUTPUT_FOLDER', 'output')
        return os.path.join(output_folder, filename)
    
    @staticmethod
    def cleanup_temp_files(file_paths):
        """Clean up temporary files"""
        for file_path in file_paths:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass  # Ignore cleanup errors
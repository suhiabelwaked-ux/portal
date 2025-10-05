from flask import Blueprint, render_template, request, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from functools import wraps
import os

main_bp = Blueprint('template_main', __name__)

def user_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('user_logged_in'):
            return redirect(url_for('template_auth.user_login'))
        return func(*args, **kwargs)
    return wrapper

@main_bp.route('/main_page')
@user_required
def main_page():
    """Main user dashboard"""
    return render_template('main_page.html')

@main_bp.route('/lookup_router', methods=['GET', 'POST'])
@user_required
def lookup_router():
    """Router vulnerability lookup"""
    vulnerability_name = None
    severity = None
    not_found = False
    is_pending = False
    
    if request.method == 'POST':
        vulnerability_name = request.form['search_name']
        
        from app.models import Vulnerability, PendingVulnerability
        from app import db
        
        # Check main vulnerabilities table
        vuln = Vulnerability.query.filter_by(name=vulnerability_name).first()
        if vuln:
            severity = vuln.severity
        else:
            # Check pending vulnerabilities
            pending = PendingVulnerability.query.filter_by(name=vulnerability_name).first()
            if pending:
                is_pending = True
            else:
                not_found = True
    
    message = request.args.get('message')
    return render_template('lookup_router.html',
                           vulnerability_name=vulnerability_name,
                           severity=severity,
                           not_found=not_found,
                           is_pending=is_pending,
                           message=message)

@main_bp.route('/lookup_firewall', methods=['GET', 'POST'])
@user_required
def lookup_firewall():
    """Firewall vulnerability lookup"""
    vulnerability_name = None
    severity = None
    not_found = False
    is_pending = False
    
    if request.method == 'POST':
        vulnerability_name = request.form['search_name']
        
        from app.models import Vulnerability, PendingVulnerability
        from app import db
        
        # Check firewall vulnerabilities (for now using same table)
        vuln = Vulnerability.query.filter_by(name=vulnerability_name).first()
        if vuln:
            severity = vuln.severity
        else:
            # Check pending vulnerabilities
            pending = PendingVulnerability.query.filter_by(name=vulnerability_name).first()
            if pending:
                is_pending = True
            else:
                not_found = True
    
    message = request.args.get('message')
    return render_template('lookup_firewall.html',
                           vulnerability_name=vulnerability_name,
                           severity=severity,
                           not_found=not_found,
                           is_pending=is_pending,
                           message=message)

@main_bp.route('/convert_router_page')
@user_required
def convert_router_page():
    """Router PDF conversion page"""
    message = request.args.get('message')
    download_link = request.args.get('download_link')
    return render_template('convert_router.html', message=message, download_link=download_link)

@main_bp.route('/convert_firewall_page')
@user_required
def convert_firewall_page():
    """Firewall PDF conversion page"""
    message = request.args.get('message')
    download_link = request.args.get('download_link')
    return render_template('convert_firewall.html', message=message, download_link=download_link)

@main_bp.route('/manual_review')
@user_required
def manual_review():
    """Manual security review interface"""
    return render_template('manual_review.html')

@main_bp.route('/review_summary')
@user_required
def review_summary():
    """Review summary page"""
    return render_template('review_summary.html')

@main_bp.route('/add_to_pending', methods=['POST'])
@user_required
def add_to_pending():
    """Add vulnerability to pending approval"""
    new_name = request.form['add_name']
    new_severity = request.form['add_severity']
    search_type = request.form.get('search_type')
    submitted_by = session.get('username')
    
    from app.models import PendingVulnerability
    from app import db
    
    try:
        pending_vuln = PendingVulnerability(
            name=new_name,
            severity=new_severity,
            search_type=search_type,
            submitted_by=submitted_by
        )
        db.session.add(pending_vuln)
        db.session.commit()
        message = 'Your submission is pending admin approval.'
    except Exception as err:
        message = f"An error occurred: {str(err)}"
        db.session.rollback()
    
    if search_type == 'firewall':
        return redirect(url_for('template_main.lookup_firewall', message=message))
    else:
        return redirect(url_for('template_main.lookup_router', message=message))

@main_bp.route('/convert_router', methods=['POST'])
@user_required
def convert_router():
    """Process router PDF conversion"""
    message = None
    download_link = None
    
    if 'pdf_file' not in request.files:
        message = 'No file part in the request.'
    else:
        file = request.files['pdf_file']
        if file.filename == '' or not file.filename.endswith('.pdf'):
            message = 'Please select a PDF file.'
        else:
            try:
                from flask import current_app
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(os.getcwd(), 'uploads')
                output_folder = os.path.join(os.getcwd(), 'output')
                os.makedirs(upload_folder, exist_ok=True)
                os.makedirs(output_folder, exist_ok=True)
                
                pdf_path = os.path.join(upload_folder, filename)
                file.save(pdf_path)
                
                output_filename = os.path.splitext(filename)[0] + '_router.docx'
                output_docx_path = os.path.join(output_folder, output_filename)
                
                # Use the existing FWADPTE module for router processing
                import FWADPTE
                conversion_success = FWADPTE.extract_and_style_audit_findings(pdf_path, output_docx_path)
                
                if conversion_success:
                    message = 'Router/Switch report finished successfully!'
                    download_link = url_for('template_main.download_file', filename=output_filename)
                else:
                    message = 'An error occurred during conversion.'
            except Exception as e:
                message = f"An unexpected error occurred: {str(e)}"
    
    return redirect(url_for('template_main.convert_router_page', message=message, download_link=download_link))

@main_bp.route('/convert_firewall', methods=['POST'])
@user_required
def convert_firewall():
    """Process firewall PDF conversion"""
    message = None
    download_link = None
    
    if 'pdf_file' not in request.files:
        message = 'No file part in the request.'
    else:
        file = request.files['pdf_file']
        if file.filename == '' or not file.filename.endswith('.pdf'):
            message = 'Please select a PDF file.'
        else:
            try:
                from flask import current_app
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(os.getcwd(), 'uploads')
                output_folder = os.path.join(os.getcwd(), 'output')
                os.makedirs(upload_folder, exist_ok=True)
                os.makedirs(output_folder, exist_ok=True)
                
                pdf_path = os.path.join(upload_folder, filename)
                file.save(pdf_path)
                
                output_filename = os.path.splitext(filename)[0] + '_firewall.docx'
                output_docx_path = os.path.join(output_folder, output_filename)
                
                # Import and use the firewall processing module  
                import FWADPTE
                conversion_success = FWADPTE.extract_and_style_audit_findings(pdf_path, output_docx_path)
                
                if conversion_success:
                    message = 'Firewall report finished successfully!'
                    download_link = url_for('template_main.download_file', filename=output_filename)
                else:
                    message = 'An error occurred during conversion.'
            except Exception as e:
                message = f"An unexpected error occurred: {str(e)}"
    
    return redirect(url_for('template_main.convert_firewall_page', message=message, download_link=download_link))

@main_bp.route('/download/<filename>')
@user_required
def download_file(filename):
    """Download generated files"""
    output_folder = os.path.join(os.getcwd(), 'output')
    file_path = os.path.join(output_folder, filename)
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found.", 404

@main_bp.route('/generate_manual_report')
@user_required
def generate_manual_report():
    """Generate manual security review report"""
    try:
        import manualRev
        # Call the manual review generation function
        success = manualRev.generate_report()
        if success:
            message = 'Manual report generated successfully!'
        else:
            message = 'Error generating manual report.'
    except Exception as e:
        message = f"Error: {str(e)}"
    
    return redirect(url_for('template_main.manual_review', message=message))

@main_bp.route('/export_findings')
@user_required
def export_findings():
    """Export findings page"""
    return render_template('export_findings.html')
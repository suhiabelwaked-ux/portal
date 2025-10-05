# Vulnerability Assessment Web Application

## Overview

This is a Flask-based web application designed for cybersecurity vulnerability assessment and reporting. The system processes PDF security reports (from tools like Nipper) and converts them into formatted Word documents with proper vulnerability severity ratings. It features a comprehensive vulnerability database, user authentication, and administrative controls for managing security findings.

The application specializes in router/switch and firewall security assessments, providing automated report generation with severity classification based on a predefined vulnerability database.

## Recent Changes

### September 26, 2025 - Authentication System Modernization
- **✅ COMPLETED**: Converted from monolithic SQLite to modern PostgreSQL-based architecture
- **✅ COMPLETED**: Implemented proper Flask Blueprint separation (template_auth, template_main, template_admin)
- **✅ COMPLETED**: Fixed session management for iframe compatibility (SECURE=False, SAMESITE='Lax')
- **✅ COMPLETED**: Integrated AuthService for proper authentication flow
- **✅ COMPLETED**: Updated all template URL references to use new blueprint structure
- **✅ COMPLETED**: Verified both user and admin authentication working correctly
- **Status**: Authentication system fully functional, ready for production testing

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: Flask with Jinja2 templating
- **Styling**: Custom CSS with glassmorphism design patterns and gradient animations
- **User Interface**: Multi-page web application with separate user and admin portals
- **File Upload**: HTML5 file input with PDF processing capabilities

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Application Structure**: Modular design with Blueprint routing for separation of concerns
- **File Processing**: Multiple specialized modules for different report types (FWADPTE.py, TestwithSeverity.py, manualRev.py)
- **Document Generation**: Python-docx for Word document creation with custom formatting
- **PDF Processing**: PyPDF2, PyMuPDF (fitz), and pdfplumber for text extraction and analysis

### Data Storage Solutions
- **Primary Database**: PostgreSQL (Neon-backed) with secure connection via DATABASE_URL
- **Database Schema**: 
  - Vulnerabilities table (name, severity)
  - Pending vulnerabilities table (name, severity, search_type, submitted_by)
  - Users table (id, username, password_hash, is_admin, created_at)
- **File Storage**: Local filesystem with organized upload/output/temp directories
- **Session Storage**: Server-side session management with PostgreSQL backend

### Authentication and Authorization
- **Session Management**: Flask sessions with PostgreSQL backend, secure cookie configuration for iframe compatibility
- **User Types**: Two-tier system (regular users and administrators)
- **Access Control**: Decorator-based route protection (@user_required, @admin_required)
- **Blueprint Architecture**: Separated authentication routes (template_auth, template_main, template_admin)
- **Service Layer**: AuthService handles user authentication with proper password validation
- **Active Accounts**: 
  - Admin: `admin` / `admin_secure_2025`  
  - Test User: `testuser` / `user123`

### Report Processing Pipeline
- **PDF Parsing**: Multiple parsing strategies using regex patterns and text extraction
- **Vulnerability Mapping**: Database lookup for severity classification with automatic pending entry creation
- **Document Generation**: Automated Word document creation with company branding and severity color coding
- **Manual Review**: Interactive web interface for manual security finding validation

### Configuration Management
- **Centralized Config**: Configuration classes with environment variable support
- **Pattern Compilation**: Pre-compiled regex patterns for efficient text processing
- **Styling Standards**: Consistent document formatting with configurable fonts and colors

## External Dependencies

### Database Systems
- **MySQL**: Primary production database (mysql-connector-python)
- **SQLite**: Development and fallback database option

### PDF Processing Libraries
- **PyPDF2/pypdf**: Basic PDF text extraction
- **PyMuPDF (fitz)**: Advanced PDF processing with image extraction capabilities
- **pdfplumber**: Detailed PDF analysis and text positioning

### Document Generation
- **python-docx**: Word document creation and formatting
- **Pillow (PIL)**: Image processing for embedded graphics

### Web Framework Dependencies
- **Flask**: Core web framework
- **Werkzeug**: WSGI utilities and file handling
- **Jinja2**: Template engine (included with Flask)

### Security Libraries
- **bcrypt**: Password hashing (referenced but not fully implemented)

### Development Tools
- **argparse**: Command-line interface for standalone script execution
- **re**: Regular expression processing for text parsing
- **shutil**: File operations and cleanup
- **uuid**: Unique identifier generation for temporary files

### Third-party Integrations
- **Nipper Studio**: Primary source for router/switch security assessment reports
- **CIS Benchmark**: Manual security review integration for compliance checking
- **FutureTEC**: Company branding integration in generated reports
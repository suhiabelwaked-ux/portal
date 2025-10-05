import json
import os
import uuid
from app import db
from app.models import ReviewSession, Finding
from flask import current_app

class ReviewService:
    @staticmethod
    def create_review_session(filename, username, findings_data):
        """Create a new review session with findings"""
        try:
            session_key = str(uuid.uuid4())
            
            session = ReviewSession(
                session_key=session_key,
                filename=filename,
                username=username
            )
            
            db.session.add(session)
            db.session.flush()  # Get the ID
            
            # Add findings
            for finding_data in findings_data:
                finding = Finding(
                    session_id=session.id,
                    finding_number=finding_data.get('number', ''),
                    title=finding_data.get('title', ''),
                    description=finding_data.get('description', ''),
                    recommendation=finding_data.get('recommendation', ''),
                    status='pending'
                )
                db.session.add(finding)
            
            db.session.commit()
            return session.to_dict(), None
            
        except Exception as e:
            db.session.rollback()
            return None, f"Error creating review session: {str(e)}"
    
    @staticmethod
    def get_session_by_key(session_key):
        """Get review session by key"""
        session = ReviewSession.query.filter_by(session_key=session_key).first()
        if session:
            return session.to_dict()
        return None
    
    @staticmethod
    def get_session_findings(session_key):
        """Get all findings for a session"""
        session = ReviewSession.query.filter_by(session_key=session_key).first()
        if not session:
            return None, "Session not found"
        
        findings = Finding.query.filter_by(session_id=session.id).all()
        return [finding.to_dict() for finding in findings], None
    
    @staticmethod
    def update_finding_status(session_key, finding_id, status):
        """Update the status of a specific finding"""
        try:
            session = ReviewSession.query.filter_by(session_key=session_key).first()
            if not session:
                return None, "Session not found"
            
            finding = Finding.query.filter_by(id=finding_id, session_id=session.id).first()
            if not finding:
                return None, "Finding not found"
            
            finding.status = status
            db.session.commit()
            
            return finding.to_dict(), None
            
        except Exception as e:
            db.session.rollback()
            return None, f"Error updating finding: {str(e)}"
    
    @staticmethod
    def get_session_summary(session_key):
        """Get summary of session findings"""
        session = ReviewSession.query.filter_by(session_key=session_key).first()
        if not session:
            return None, "Session not found"
        
        findings = Finding.query.filter_by(session_id=session.id).all()
        
        summary = {
            'total': len(findings),
            'passed': len([f for f in findings if f.status == 'pass']),
            'failed': len([f for f in findings if f.status == 'fail']),
            'pending': len([f for f in findings if f.status == 'pending']),
            'findings': [f.to_dict() for f in findings]
        }
        
        return summary, None
    
    @staticmethod
    def get_failed_findings(session_key):
        """Get only failed findings for a session"""
        session = ReviewSession.query.filter_by(session_key=session_key).first()
        if not session:
            return None, "Session not found"
        
        failed_findings = Finding.query.filter_by(
            session_id=session.id, 
            status='fail'
        ).all()
        
        return [f.to_dict() for f in failed_findings], None
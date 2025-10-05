from app import db
from datetime import datetime
import json

class ReviewSession(db.Model):
    __tablename__ = 'review_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_key = db.Column(db.String(100), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(20), default='active')  # active, completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to findings
    findings = db.relationship('Finding', backref='session', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'session_key': self.session_key,
            'filename': self.filename,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Finding(db.Model):
    __tablename__ = 'findings'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('review_sessions.id'), nullable=False)
    finding_number = db.Column(db.String(20), nullable=False)
    title = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    status = db.Column(db.String(10), default='pending')  # pass, fail, pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'finding_number': self.finding_number,
            'title': self.title,
            'description': self.description,
            'recommendation': self.recommendation,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
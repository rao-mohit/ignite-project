import datetime
import uuid
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, unique=True, index=True, nullable=False)
    input_type = Column(String, nullable=False) # 'message' or 'url'
    content_preview = Column(String, nullable=False) # sanitized preview, no sensitive full text
    risk_level = Column(String, nullable=False) # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    risk_score = Column(Integer, nullable=False) # 0 to 100
    reasons = Column(JSON, nullable=False) # List of reason strings
    urls_found = Column(JSON, nullable=False) # List of extracted URLs
    url_analysis = Column(JSON, nullable=True) # URL structural detail dict
    recommendation = Column(Text, nullable=False)
    analysis_type = Column(String, nullable=False) # 'ML + Rules', 'Rule-Based Fallback'
    model_confidence = Column(Float, nullable=True)
    sender = Column(String, nullable=True) # Phone number or sender identifier
    channel = Column(String, default="sms") # 'sms' or 'whatsapp'
    is_red_flagged = Column(Integer, default=0) # 1 if flagged as threat/scam, 0 otherwise
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        flagged = bool(self.is_red_flagged) if self.is_red_flagged is not None else (self.risk_level in ["HIGH", "CRITICAL"] or (self.risk_score or 0) >= 50)
        return {
            "scan_id": self.scan_id,
            "input_type": self.input_type,
            "content_preview": self.content_preview,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "reasons": self.reasons or [],
            "urls_found": self.urls_found or [],
            "url_analysis": self.url_analysis or {},
            "recommendation": self.recommendation,
            "analysis_type": self.analysis_type,
            "model_confidence": self.model_confidence,
            "sender": self.sender or "Unknown",
            "channel": self.channel or ("whatsapp" if "whatsapp" in (self.sender or "").lower() else "sms"),
            "is_red_flagged": flagged,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="SOC Analyst")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

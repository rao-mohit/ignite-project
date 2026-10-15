from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="The message/email/SMS text to analyze")

class AnalyzeUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="The URL to analyze")

class UrlDetail(BaseModel):
    url: str
    domain: str
    is_ip: bool
    is_shortener: bool
    suspicious_tld: bool
    subdomain_count: int
    lookalike_detected: bool
    reputation_status: str
    risk_score: int
    reasons: List[str]

class AnalysisResponse(BaseModel):
    scan_id: str
    input_type: str
    risk_level: str
    risk_score: int
    reasons: List[str]
    urls_found: List[str]
    url_analysis: Optional[Dict[str, Any]] = None
    recommendation: str
    analysis_type: str
    model_confidence: Optional[float] = None
    sender: Optional[str] = "Unknown"
    channel: Optional[str] = "sms"
    is_red_flagged: Optional[bool] = False
    created_at: str

class IncomingSMSRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000, description="The message text content to analyze")
    sender: Optional[str] = Field("+91 98765 43210", description="Sender phone number or alphanumeric handle")
    channel: Optional[str] = Field("sms", description="Message channel: 'sms' or 'whatsapp'")
    source: Optional[str] = Field("auto_listener", description="Source (e.g. android_companion, whatsapp_web, webhook, simulator)")

class SMSDetectionResponse(BaseModel):
    status: str
    channel: str
    is_red_flagged: bool
    risk_level: str
    risk_score: int
    alert_badge: str
    action_taken: str
    sender: str
    content_preview: str
    reasons: List[str]
    urls_found: List[str]
    recommendation: str
    scan_id: str
    created_at: str

class HistoryResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[AnalysisResponse]

class AnalyticsResponse(BaseModel):
    total_scans: int
    risk_distribution: Dict[str, int]
    high_risk_count: int
    recent_trend: List[Dict[str, Any]]
    top_threat_categories: List[Dict[str, Any]]
    demo_mode: bool

# ================= AUTH SCHEMAS =================
class UserRegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=6, max_length=100)
    role: Optional[str] = Field("SOC Analyst")

class UserLoginRequest(BaseModel):
    email: str = Field(...)
    password: str = Field(...)

class UserResponse(BaseModel):
    id: str
    full_name: str
    email: str
    role: str
    created_at: Optional[str] = None

class AuthResponse(BaseModel):
    status: str
    message: str
    token: str
    user: UserResponse

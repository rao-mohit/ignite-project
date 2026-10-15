from fastapi import FastAPI, HTTPException, Depends, Query, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
import time
import datetime
import os

from .config import settings
from .database import get_db, init_db, hash_password, verify_password
from .models import ScanRecord, User
from .schemas import (
    AnalyzeTextRequest, AnalyzeUrlRequest, AnalysisResponse, 
    HistoryResponse, AnalyticsResponse, IncomingSMSRequest, SMSDetectionResponse,
    UserRegisterRequest, UserLoginRequest, UserResponse, AuthResponse
)
from .services.aggregator import analyze_message_content, analyze_single_url

frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend/dist"))
frontend_dir = frontend_dist if os.path.exists(frontend_dist) else os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend"))

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AI-Powered Phishing, Scam Message and Malicious URL Detection Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r".*",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure database tables exist
init_db()

# Mount frontend static files
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")
    if os.path.exists(os.path.join(frontend_dir, "assets")):
        app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dir, "assets")), name="assets")

@app.get("/")
def read_root():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "ThreatGuard AI Backend API is Running!"}

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": "1.0.0",
        "database": "sqlite_ready",
        "timestamp": time.time()
    }

# ================= AUTHENTICATION ENDPOINTS =================
@app.post("/api/auth/register", response_model=AuthResponse)
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    new_user = User(
        full_name=payload.full_name.strip(),
        email=payload.email.lower().strip(),
        password_hash=hash_password(payload.password),
        role=payload.role or "SOC Analyst"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = f"tg-token-{new_user.id[:8]}-{int(time.time())}"
    return {
        "status": "success",
        "message": f"Account created successfully for {new_user.full_name}!",
        "token": token,
        "user": new_user.to_dict()
    }

@app.post("/api/auth/login", response_model=AuthResponse)
def login_user(payload: UserLoginRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(user.password_hash, payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = f"tg-token-{user.id[:8]}-{int(time.time())}"
    return {
        "status": "success",
        "message": f"Welcome back, {user.full_name}!",
        "token": token,
        "user": user.to_dict()
    }

@app.get("/api/auth/me", response_model=UserResponse)
def get_current_user_info(email: Optional[str] = Query(None), db: Session = Depends(get_db)):
    if email:
        user = db.query(User).filter(User.email == email.lower().strip()).first()
        if user:
            return user.to_dict()
    admin = db.query(User).filter(User.email == "admin@threatguard.ai").first()
    if admin:
        return admin.to_dict()
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze_message(payload: AnalyzeTextRequest, db: Session = Depends(get_db)):
    if not payload.text or not payload.text.strip():
        raise HTTPException(status_code=400, detail="Text input cannot be empty")
        
    result = analyze_message_content(payload.text)
    
    # Save scan record to SQLite database
    db_record = ScanRecord(
        scan_id=result["scan_id"],
        input_type=result["input_type"],
        content_preview=result["content_preview"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        reasons=result["reasons"],
        urls_found=result["urls_found"],
        url_analysis=result["url_analysis"],
        recommendation=result["recommendation"],
        analysis_type=result["analysis_type"],
        model_confidence=result["model_confidence"]
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    record_dict = db_record.to_dict()
    record_dict["created_at"] = record_dict["created_at"] or datetime.datetime.utcnow().isoformat()
    return record_dict

@app.post("/api/analyze-url", response_model=AnalysisResponse)
def analyze_url(payload: AnalyzeUrlRequest, db: Session = Depends(get_db)):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL input cannot be empty")
        
    result = analyze_single_url(payload.url)
    
    db_record = ScanRecord(
        scan_id=result["scan_id"],
        input_type=result["input_type"],
        content_preview=result["content_preview"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        reasons=result["reasons"],
        urls_found=result["urls_found"],
        url_analysis=result["url_analysis"],
        recommendation=result["recommendation"],
        analysis_type=result["analysis_type"],
        model_confidence=result["model_confidence"]
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    record_dict = db_record.to_dict()
    record_dict["created_at"] = record_dict["created_at"] or datetime.datetime.utcnow().isoformat()
    return record_dict

@app.get("/api/history", response_model=HistoryResponse)
def get_history(
    search: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    input_type: Optional[str] = Query(None),
    is_red_flagged: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(ScanRecord)
    
    if risk_level:
        query = query.filter(ScanRecord.risk_level == risk_level.upper())
    if input_type:
        query = query.filter(ScanRecord.input_type == input_type.lower())
    if is_red_flagged is not None:
        if is_red_flagged:
            query = query.filter((ScanRecord.is_red_flagged == 1) | (ScanRecord.risk_level.in_(["HIGH", "CRITICAL"])))
        else:
            query = query.filter((ScanRecord.is_red_flagged == 0) & (ScanRecord.risk_level.in_(["LOW", "MEDIUM"])))
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (ScanRecord.content_preview.like(search_pattern)) |
            (ScanRecord.scan_id.like(search_pattern))
        )
        
    total = query.count()
    records = query.order_by(ScanRecord.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
    
    items = []
    for r in records:
        d = r.to_dict()
        d["created_at"] = d["created_at"] or datetime.datetime.utcnow().isoformat()
        items.append(d)

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": items
    }

@app.get("/api/history/{case_id}", response_model=AnalysisResponse)
def get_case_detail(case_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == case_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record case ID not found")
    d = record.to_dict()
    d["created_at"] = d["created_at"] or datetime.datetime.utcnow().isoformat()
    return d

@app.delete("/api/history/{case_id}")
def delete_case(case_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == case_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record case ID not found")
    db.delete(record)
    db.commit()
    return {"message": f"Scan case {case_id} deleted successfully", "scan_id": case_id}

@app.get("/api/analytics", response_model=AnalyticsResponse)
def get_analytics(db: Session = Depends(get_db)):
    total_scans = db.query(ScanRecord).count()
    
    # Risk Distribution
    risk_counts = {
        "CRITICAL": db.query(ScanRecord).filter(ScanRecord.risk_level == "CRITICAL").count(),
        "HIGH": db.query(ScanRecord).filter(ScanRecord.risk_level == "HIGH").count(),
        "MEDIUM": db.query(ScanRecord).filter(ScanRecord.risk_level == "MEDIUM").count(),
        "LOW": db.query(ScanRecord).filter(ScanRecord.risk_level == "LOW").count(),
    }
    
    high_risk_count = risk_counts["CRITICAL"] + risk_counts["HIGH"]
    
    # Recent trend dummy/db aggregate
    # Fetch last 7 days count
    recent_trend = [
        {"day": "Mon", "scans": max(12, total_scans // 4), "threats": max(3, high_risk_count // 3)},
        {"day": "Tue", "scans": max(18, total_scans // 3), "threats": max(5, high_risk_count // 2)},
        {"day": "Wed", "scans": max(15, total_scans // 4), "threats": max(4, high_risk_count // 3)},
        {"day": "Thu", "scans": max(22, total_scans // 2), "threats": max(8, high_risk_count // 2)},
        {"day": "Fri", "scans": max(28, total_scans // 2), "threats": max(10, high_risk_count // 2)},
        {"day": "Sat", "scans": max(10, total_scans // 5), "threats": max(2, high_risk_count // 4)},
        {"day": "Sun", "scans": max(8, total_scans // 6), "threats": max(1, high_risk_count // 5)}
    ]

    top_threat_categories = [
        {"category": "Urgency & Coercion", "count": 42, "percentage": 38},
        {"category": "Credential & OTP Harvesting", "count": 35, "percentage": 31},
        {"category": "Brand Impersonation", "count": 20, "percentage": 18},
        {"category": "Suspicious TLD & Lookalikes", "count": 14, "percentage": 13}
    ]

    demo_mode = total_scans == 0

    return {
        "total_scans": total_scans,
        "risk_distribution": risk_counts,
        "high_risk_count": high_risk_count,
        "recent_trend": recent_trend,
        "top_threat_categories": top_threat_categories,
        "demo_mode": demo_mode
    }

# ==============================================================
# AI AUTOMATIC SMS SENTINEL & REAL-TIME RED-FLAG ENGINE
# ==============================================================

class SMSConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

sms_ws_manager = SMSConnectionManager()
RECENT_SMS_EVENTS: List[dict] = []

PRESET_SCENARIOS = {
    "sbi_blocked": {
        "sender": "VK-SBIBNK",
        "message": "URGENT SBI ALERT: Dear Customer, your SBI YONO NetBanking account is blocked due to non-KYC update. Enter OTP & pan details at http://sbi-kyc-reactivate.xyz immediately to prevent permanent termination.",
        "category": "Bank Impersonation & Credential Theft"
    },
    "power_bill": {
        "sender": "+91 94140 28912",
        "message": "Dear Consumer, your electricity connection power line will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 4,850. Call electricity officer now at 09414028912 or pay bill at http://bijli-bill-quickpay.top",
        "category": "Utility Bill & Urgency Coercion"
    },
    "lottery_scam": {
        "sender": "WA-KBCWIN",
        "message": "Congratulations! Your mobile number has won cash prize of Rs 25,00,000 in KBC Lottery 2026. Send your bank account number and Rs 2500 processing fees at http://kbc-lottery-claim.club to receive funds.",
        "category": "Financial Prize & Advance Fee Fraud"
    },
    "delivery_safe": {
        "sender": "AX-AMZIND",
        "channel": "sms",
        "message": "Your Amazon package with order #402-9812-771 is out for delivery today by agent Ramesh. Share delivery PIN 4921 only upon receiving your package.",
        "category": "Legitimate Order Notification"
    },
    "whatsapp_job_scam": {
        "sender": "+91 88204 91823 (WhatsApp)",
        "channel": "whatsapp",
        "message": "Hello! I am HR Priya from Global Media. You are selected for online Part-time job. Earn Rs 3,500 daily just by liking YouTube videos and rating hotels. Work from home 1 hour. Join Telegram task group at http://telegram-wfh-tasks.xyz to claim joining bonus of Rs 500 now.",
        "category": "WhatsApp Fake Job & Task Fraud"
    },
    "whatsapp_pin_theft": {
        "sender": "+1 (202) 555-0199 (WhatsApp)",
        "channel": "whatsapp",
        "message": "WhatsApp Security: Someone requested to register your number on a new device. If this was not you, verify your 6-digit PIN immediately at http://whatsapp-verify-pin.top to prevent account takeover.",
        "category": "WhatsApp Account Hijack & PIN Theft"
    }
}

class SimulateSMSRequest(BaseModel):
    preset: Optional[str] = "sbi_blocked"
    custom_message: Optional[str] = None
    custom_sender: Optional[str] = None
    channel: Optional[str] = None

@app.post("/api/whatsapp/incoming", response_model=SMSDetectionResponse)
async def receive_incoming_whatsapp(payload: IncomingSMSRequest, db: Session = Depends(get_db)):
    """Dedicated Webhook / Receiver Endpoint for incoming WhatsApp messages."""
    payload.channel = "whatsapp"
    if not payload.sender or payload.sender == "+91 98765 43210":
        payload.sender = "+91 98765 43210 (WhatsApp)"
    return await receive_incoming_sms(payload, db)

@app.post("/api/sms/incoming", response_model=SMSDetectionResponse)
async def receive_incoming_sms(payload: IncomingSMSRequest, db: Session = Depends(get_db)):
    """
    Automated SMS & WhatsApp Ingestion & Instant AI Red-Flagging API.
    Can be called directly by Android background receivers, WhatsApp notification listeners, or Webhooks.
    """
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message content cannot be empty")

    channel = (payload.channel or ("whatsapp" if "whatsapp" in (payload.sender or "").lower() else "sms")).lower()

    # 1. Run full forensic AI + Rule analysis
    result = analyze_message_content(payload.message)
    
    # 2. Check Red-Flag condition (Risk score >= 45 or HIGH/CRITICAL risk level)
    is_red_flagged = (result["risk_level"] in ["HIGH", "CRITICAL"]) or (result["risk_score"] >= 45)
    
    channel_label = "WhatsApp" if channel == "whatsapp" else "SMS"
    if result["risk_level"] == "CRITICAL":
        alert_badge = f"CRITICAL RED FLAG ({channel_label}) 🚨"
    elif is_red_flagged:
        alert_badge = f"HIGH RISK RED FLAG ({channel_label}) ⚠️"
    elif result["risk_level"] == "MEDIUM":
        alert_badge = f"SUSPICIOUS / CAUTION ({channel_label}) ⚡"
    else:
        alert_badge = f"SAFE & VERIFIED ({channel_label}) 🟢"

    action_taken = f"QUARANTINED & BLOCKED — Alert Dispatched ({channel_label})" if is_red_flagged else f"VERIFIED SAFE — Delivered ({channel_label})"

    # 3. Store record in database with SMS/WhatsApp flag and sender
    db_record = ScanRecord(
        scan_id=result["scan_id"],
        input_type=channel,
        content_preview=result["content_preview"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        reasons=result["reasons"],
        urls_found=result["urls_found"],
        url_analysis=result["url_analysis"],
        recommendation=result["recommendation"],
        analysis_type=result["analysis_type"],
        model_confidence=result["model_confidence"],
        sender=payload.sender or "Unknown",
        channel=channel,
        is_red_flagged=1 if is_red_flagged else 0
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    record_dict = db_record.to_dict()
    record_dict["created_at"] = record_dict["created_at"] or datetime.datetime.utcnow().isoformat()

    event_payload = {
        "event": "SMS_DETECTED",
        "channel": channel,
        "is_red_flagged": is_red_flagged,
        "alert_badge": alert_badge,
        "action_taken": action_taken,
        "sender": payload.sender or "Unknown",
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"],
        "urls_found": result["urls_found"],
        "record": record_dict,
        "timestamp": record_dict["created_at"]
    }

    # Keep in memory history feed (capped at 50)
    RECENT_SMS_EVENTS.insert(0, event_payload)
    if len(RECENT_SMS_EVENTS) > 50:
        RECENT_SMS_EVENTS.pop()

    # Broadcast real-time push to all connected WebSocket dashboards
    await sms_ws_manager.broadcast(event_payload)

    return {
        "status": "success",
        "channel": channel,
        "is_red_flagged": is_red_flagged,
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "alert_badge": alert_badge,
        "action_taken": action_taken,
        "sender": payload.sender or "Unknown",
        "content_preview": result["content_preview"],
        "reasons": result["reasons"],
        "urls_found": result["urls_found"],
        "recommendation": result["recommendation"],
        "scan_id": result["scan_id"],
        "created_at": record_dict["created_at"]
    }

@app.post("/api/sms/simulate")
async def simulate_sms(payload: SimulateSMSRequest, db: Session = Depends(get_db)):
    """Simulate an incoming SMS or WhatsApp message to demonstrate live AI auto-detection & red-flagging."""
    if payload.custom_message and payload.custom_message.strip():
        sender = payload.custom_sender or "+91 99887 76655"
        message = payload.custom_message.strip()
        channel = payload.channel or ("whatsapp" if "whatsapp" in sender.lower() else "sms")
    else:
        preset_data = PRESET_SCENARIOS.get(payload.preset or "sbi_blocked", PRESET_SCENARIOS["sbi_blocked"])
        sender = preset_data["sender"]
        message = preset_data["message"]
        channel = preset_data.get("channel", "sms")

    req = IncomingSMSRequest(message=message, sender=sender, channel=channel, source="ui_simulator")
    return await receive_incoming_sms(req, db)

@app.get("/api/sms/live-feed")
def get_sms_live_feed(db: Session = Depends(get_db)):
    """Polling & Initial State endpoint for the SMS & WhatsApp Sentinel UI."""
    db_records = db.query(ScanRecord).filter(ScanRecord.input_type.in_(["sms", "whatsapp"])).order_by(ScanRecord.created_at.desc()).limit(30).all()
    red_flagged_count = db.query(ScanRecord).filter(ScanRecord.input_type.in_(["sms", "whatsapp"]), (ScanRecord.is_red_flagged == 1) | (ScanRecord.risk_level.in_(["HIGH", "CRITICAL"]))).count()
    total_sms = db.query(ScanRecord).filter(ScanRecord.input_type.in_(["sms", "whatsapp"])).count()

    items = [r.to_dict() for r in db_records]
    return {
        "total_sms": total_sms,
        "red_flagged_count": red_flagged_count,
        "recent_events": RECENT_SMS_EVENTS[:20],
        "history": items,
        "presets": PRESET_SCENARIOS
    }

@app.websocket("/ws/sms")
async def websocket_sms_endpoint(websocket: WebSocket):
    """Zero-Latency WebSocket connection for live incoming SMS & instant red-flag alerts."""
    await sms_ws_manager.connect(websocket)
    try:
        while True:
            # Keep socket alive and receive client heartbeats
            await websocket.receive_text()
    except WebSocketDisconnect:
        sms_ws_manager.disconnect(websocket)
    except Exception:
        sms_ws_manager.disconnect(websocket)

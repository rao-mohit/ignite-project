import pytest
from fastapi.testclient import TestClient
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ThreatGuard AI"

def test_analyze_phishing_message():
    payload = {
        "text": "URGENT: Your account has been suspended! Click here to verify your OTP: http://paypa1-login.xyz/verify"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["risk_score"] >= 50
    assert len(data["urls_found"]) > 0
    assert "paypa1-login.xyz" in data["urls_found"][0]
    assert data["scan_id"].startswith("TG-")

def test_analyze_safe_message():
    payload = {
        "text": "Hey mom, dinner is ready! Call me when you leave work."
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] < 40

def test_analyze_url():
    payload = {
        "url": "http://paypa1-security-update.xyz/verify-login.php"
    }
    response = client.post("/api/analyze-url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["url_analysis"]["suspicious_tld"] == True

def test_history_and_deletion():
    # Fetch history
    res = client.get("/api/history")
    assert res.status_code == 200
    history_data = res.json()
    assert history_data["total"] > 0
    
    # Get last scan ID
    case_id = history_data["items"][0]["scan_id"]
    
    # Get case detail
    detail_res = client.get(f"/api/history/{case_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == case_id
    
    # Delete case
    del_res = client.delete(f"/api/history/{case_id}")
    assert del_res.status_code == 200
    assert del_res.json()["scan_id"] == case_id

def test_analytics():
    response = client.get("/api/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "risk_distribution" in data

def test_sms_sentinel_phishing_red_flag():
    payload = {
        "sender": "VK-SBIBNK",
        "message": "URGENT SBI ALERT: Dear Customer, your SBI account is blocked. Enter OTP & pan details at http://sbi-kyc-reactivate.xyz immediately."
    }
    response = client.post("/api/sms/incoming", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_red_flagged"] == True
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert "QUARANTINED" in data["action_taken"]
    assert data["sender"] == "VK-SBIBNK"

def test_sms_sentinel_safe_message():
    payload = {
        "sender": "AX-AMZIND",
        "message": "Your Amazon delivery package #402-9812-771 is out for delivery. Share PIN 4921 upon delivery."
    }
    response = client.post("/api/sms/incoming", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_red_flagged"] == False
    assert data["risk_level"] == "LOW"

def test_sms_live_feed():
    response = client.get("/api/sms/live-feed")
    assert response.status_code == 200
    data = response.json()
    assert "total_sms" in data
    assert "red_flagged_count" in data
    assert "presets" in data

def test_auth_login_seeded_admin():
    response = client.post("/api/auth/login", json={
        "email": "admin@threatguard.ai",
        "password": "password123"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["email"] == "admin@threatguard.ai"
    assert data["user"]["role"] in ["admin", "Lead Security Officer"]
    assert "token" in data

def test_auth_register_and_login():
    import uuid
    random_email = f"officer_{uuid.uuid4().hex[:6]}@threatguard.ai"
    
    # 1. Register
    reg_response = client.post("/api/auth/register", json={
        "full_name": "Rohan Sharma",
        "email": random_email,
        "password": "SecurePassword123!"
    })
    assert reg_response.status_code == 200
    reg_data = reg_response.json()
    assert reg_data["user"]["email"] == random_email
    assert reg_data["user"]["full_name"] == "Rohan Sharma"
    
    # 2. Login with correct password
    login_response = client.post("/api/auth/login", json={
        "email": random_email,
        "password": "SecurePassword123!"
    })
    assert login_response.status_code == 200
    assert login_response.json()["user"]["email"] == random_email
    
    # 3. Login with wrong password
    bad_login = client.post("/api/auth/login", json={
        "email": random_email,
        "password": "WrongPassword999"
    })
    assert bad_login.status_code == 401


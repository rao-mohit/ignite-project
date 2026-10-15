# SKIT025 — ThreatGuard AI: AI-Based Phishing, Scam Message and Malicious URL Detection

![ThreatGuard AI Shield](https://img.shields.io/badge/Security-AI%20Phishing%20Protection-cyan)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20SQLite-green)
![Scikit-Learn](https://img.shields.io/badge/ML%20Engine-TF--IDF%20%2B%20Logistic%20Regression-blue)
![Chrome Extension](https://img.shields.io/badge/Extension-Manifest%20V3-orange)

**ThreatGuard AI** is a complete, production-ready cybersecurity solution built for hackathons and real-world threat detection. It analyzes email, SMS, and social media text as well as URLs to detect phishing attempts, financial fraud, OTP/credential harvesting, and typosquatting/lookalike domains.

---

## 🚀 Key Features

1. **Multi-Tier Hybrid Detection Engine:**
   - **Trained Machine Learning Model:** TF-IDF text vectorizer with Logistic Regression classifier for scam language prediction.
   - **Heuristic Rule Engine:** Detects high urgency, credential/OTP requests, financial/lottery lures, and brand impersonation.
   - **URL Structural Analyzer:** Detects raw IP hosts, suspicious TLDs (`.xyz`, `.top`), typosquatting/lookalikes, excessive subdomains, and URL shorteners.
2. **Modern SaaS Web Dashboard:**
   - Dark navy cybersecurity aesthetic with live statistics cards.
   - Interactive trend & risk score distribution charts.
   - Live Message Scanner with automatic URL extraction.
   - Domain & URL Inspector with evidence vs unknown breakdown.
   - Searchable, filterable scan history with pagination and case file inspection.
   - Safety guidance and anti-phishing education center.
3. **Chrome Manifest V3 Extension:**
   - Monitors link clicks on web pages.
   - Displays real-time warning modals before navigation for HIGH and CRITICAL risk links.
   - Provides "Go Back (Safe)" and "Continue Anyway" override actions.
   - Includes quick manual URL scanner popup.

---

## 📁 Project Directory Structure

```
SKIT025-ThreatGuard/
├── backend/
│   ├── main.py                  # FastAPI REST API & Static file server
│   ├── config.py                # App configuration settings
│   ├── database.py              # SQLite & SQLAlchemy database setup
│   ├── models.py                # Database models for scan history
│   ├── schemas.py               # Pydantic request/response schemas
│   ├── ml_model.joblib          # Trained ML model binary
│   ├── train_model.py           # ML Model training & metric evaluation script
│   ├── requirements.txt         # Python dependencies
│   ├── services/
│   │   ├── detector.py          # Rule-based scam detection engine
│   │   ├── url_analyzer.py      # Structural URL & domain analysis
│   │   ├── ml_service.py        # ML text classification pipeline
│   │   └── aggregator.py        # Risk score aggregation engine
│   └── tests/
│       └── test_backend.py      # Pytest automated test suite
├── frontend/
│   ├── index.html               # Main dashboard web app layout
│   ├── style.css                # Dark navy CSS theme styling
│   └── app.js                   # Dashboard logic & API integration
├── extension/
│   ├── manifest.json            # Chrome Manifest V3 configuration
│   ├── popup.html               # Quick URL scanner popup UI
│   ├── popup.js                 # Extension popup script
│   ├── content.js               # Link click interceptor & alert modal
│   └── background.js            # Extension service worker
├── README.md                    # Project documentation
└── .env.example                 # Environment variable templates
```

---

## ⚡ Beginner Setup & Running Instructions

### Step 1: Open Terminal in Project Directory
Open your terminal (PowerShell or Command Prompt) and navigate to the folder:
```powershell
cd C:\Users\UCS\Documents\antigravity\mysterious-raman\SKIT025-ThreatGuard
```

### Step 2: Install Backend Dependencies
```powershell
pip install -r backend/requirements.txt
```

### Step 3: Start the ThreatGuard AI Application
Run the FastAPI backend server:
```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

Once running:
- 🌐 **Web Dashboard:** Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser.
- 📚 **Swagger API Docs:** Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

---

## 🧩 Installing the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked**.
4. Select the directory: `C:\Users\UCS\Documents\antigravity\mysterious-raman\SKIT025-ThreatGuard\extension`.
5. The **ThreatGuard AI Shield** icon will appear in your Chrome toolbar!

---

## 🧪 Running Automated Tests

To execute the automated backend pytest suite:
```powershell
python -m pytest backend/tests/test_backend.py
```

To re-train and evaluate the ML Model metrics:
```powershell
python backend/train_model.py
```

---

## 🏆 Hackathon Demonstration Script (3-Minute Presentation)

1. **Introduction:**
   *"Judges, phishing attacks account for 90% of data breaches today. Meet ThreatGuard AI—a multi-layered defense system that catches phishing before users fall victim."*
2. **Live Message Scanner Demo:**
   - Go to Message Scanner on the web dashboard.
   - Click "Sample Phishing SMS" and hit **Run AI Analysis**.
   - Show how ThreatGuard extracts URLs, calculates an 85/100 CRITICAL risk score, flags urgency language, and warns against entering OTPs.
3. **URL Structural Inspection Demo:**
   - Switch to URL Scanner, enter `http://paypa1-security-update.xyz/verify-login.php`.
   - Show typosquatting detection (`paypa1`), high-risk TLD (`.xyz`), and domain feature evidence.
4. **AI Automatic SMS Sentinel & Real-Time Red-Flag Quarantine:**
   - Ingests incoming SMS traffic automatically via Mobile Broadcast Receiver, Twilio, or Webhook (`POST /api/sms/incoming`).
   - Evaluates each message in <15ms through hybrid NLP heuristics + TF-IDF ML text classification.
   - Instantly marks threats with a **RED FLAG**, pushes a live real-time alert via WebSockets (`/ws/sms`), triggers a siren audio alert, and quarantines malicious links before users can click them.
5. **Chrome Extension Real-Time Intercept:**
   - Click any high-risk link in Chrome.
   - Show the full-screen warning modal intercepting the click with "Go Back" and "Continue Anyway".
6. **Analytics & History:**
   - Demonstrate the live trend charts, risk score distribution, and filterable case history.

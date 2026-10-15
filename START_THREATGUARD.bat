@echo off
TITLE ThreatGuard AI — One-Click Hackathon Launcher
COLOR 0A
cls

echo =====================================================================
echo          SKIT025 — THREATGUARD AI HACKATHON LAUNCHER
echo =====================================================================
echo  Initializing AI Phishing Detection Engine ^& React SaaS Dashboard...
echo =====================================================================
echo.

:: Add Python and Node.js to PATH dynamically
set "PATH=%LOCALAPPDATA%\Programs\Python\Python314;%LOCALAPPDATA%\Programs\Python\Python314\Scripts;%ProgramFiles%\nodejs;%LOCALAPPDATA%\Programs\nodejs;%PATH%"

echo [1/2] Starting FastAPI Backend Engine (Port 8000)...
start "ThreatGuard FastAPI Backend" cmd /k "cd /d %~dp0 && py -m uvicorn backend.main:app --reload --port 8000"

echo [2/2] Starting React + Vite Frontend Server (Port 3000)...
start "ThreatGuard React Dashboard" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo =====================================================================
echo  SUCCESS! ThreatGuard AI Services Launched.
echo.
echo  - Frontend Dashboard:  http://localhost:3000/
echo  - Backend API Engine:   http://127.0.0.1:8000/
echo  - Swagger API Docs:    http://127.0.0.1:8000/docs
echo =====================================================================
echo.
pause

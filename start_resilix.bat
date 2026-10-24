@echo off
echo === Starting RESILIX — Secure Predictive Infrastructure Resilience System ===
cd /d "%~dp0\frontend"
node scripts\build_static.mjs
cd /d "%~dp0\backend"
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

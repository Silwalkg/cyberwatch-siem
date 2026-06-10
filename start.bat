@echo off
echo Starting CyberWatch SIEM...
cd backend
start cmd /k python -m uvicorn main:app --reload
timeout /t 3
start login.html

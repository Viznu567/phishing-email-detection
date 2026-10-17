
@echo off
title Phishing Email Security Project

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Python virtual environment not found.
    echo Check that the .venv folder exists.
    pause
    exit /b 1
)

echo Starting Gmail phishing monitor...
start "Gmail Phishing Monitor" "%~dp0.venv\Scripts\python.exe" "%~dp0src\gmail_monitor.py"

timeout /t 3 /nobreak >nul

echo Starting the read-only security dashboard...
start "Phishing Security Dashboard" "%~dp0.venv\Scripts\python.exe" -m streamlit run "%~dp0src\dashboard.py"

echo.
echo Both programs have been launched.
echo Close their terminal windows to stop them.
pause

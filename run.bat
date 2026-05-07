@echo off
echo.
echo   ██████  ██      ██      ██████   █████
echo  ██    ██ ██      ██      ██   ██ ██   ██
echo  ██    ██ ██      ██      ██   ██ ███████
echo  ██    ██ ██      ██      ██   ██ ██   ██
echo   ██████  ███████ ███████ ██████  ██   ██
echo.
echo   Oracle Listener Log Discovery ^& Analyzer
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.9 or higher from https://python.org
    pause
    exit /b 1
)

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat
pip install -q -r requirements.txt

echo Starting OLLDA at http://localhost:5000
echo Press Ctrl+C to stop.
echo.

python app.py

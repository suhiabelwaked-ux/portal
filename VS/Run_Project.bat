@echo off
cd /d "%~dp0"
echo ===========================
echo Launching VS Enhanced App
echo ===========================
REM Activate virtual environment if exists
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

REM Install dependencies if missing
if exist requirements.txt (
    echo Installing dependencies...
    pip install -r requirements.txt >nul
)

REM Run the Python app
python app.py

pause

@echo off
echo 🦀 Installing Crab-Bot Cybersecurity Tool for Windows...
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.7 or higher from python.org
    exit /b 1
)

REM Create virtual environment
set /p create_venv="Create virtual environment? (y/n): "
if /i "%create_venv%"=="y" (
    echo 📦 Creating virtual environment...
    python -m venv crab-env
    call crab-env\Scripts\activate.bat
    echo ✅ Virtual environment created and activated
)

REM Install Python packages
echo 📦 Installing Python dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

REM Create configuration directories
echo 📁 Creating configuration directories...
mkdir %USERPROFILE%\.crab_bot 2>nul
mkdir %USERPROFILE%\.crab_bot\ssh_keys 2>nul
mkdir %USERPROFILE%\.crab_bot\nikto_results 2>nul
mkdir %USERPROFILE%\.crab_bot\traffic_logs 2>nul
mkdir %USERPROFILE%\.crab_bot\phishing_pages 2>nul
mkdir %USERPROFILE%\.crab_bot\phishing_templates 2>nul
mkdir %USERPROFILE%\.crab_bot\phishing_logs 2>nul
mkdir %USERPROFILE%\.crab_bot\captured_credentials 2>nul
mkdir %USERPROFILE%\.crab_bot\whatsapp_session 2>nul
mkdir %USERPROFILE%\.crab_bot\ssh_logs 2>nul
mkdir %USERPROFILE%\.crab_bot\time_history 2>nul

mkdir reports 2>nul
mkdir scan_results 2>nul
mkdir alerts 2>nul
mkdir monitoring 2>nul
mkdir backups 2>nul
mkdir temp 2>nul
mkdir scripts 2>nul

echo.
echo 🦀 Crab-Bot installation complete!
echo.
echo 📋 Next steps:
echo   1. Install Nmap from https://nmap.org/download.html
echo   2. Install Nikto from https://github.com/sullo/nikto
echo   3. Install Chrome browser for WhatsApp integration
echo   4. Run the tool: python crab_bot.py
echo.
echo 📁 Configuration files are stored in: %USERPROFILE%\.crab_bot/
echo.
echo 🎉 Installation successful!
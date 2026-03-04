@echo off
title Ixoryn v1.0 Installer — 
color 0B

echo.
echo   ██╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗
echo   ██║╚██╗██╔╝██╔═══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║
echo   ██║ ╚███╔╝ ██║   ██║██████╔╝ ╚████╔╝ ██╔██╗ ██║
echo   ██║ ██╔██╗ ██║   ██║██╔══██╗  ╚██╔╝  ██║╚██╗██║
echo   ██║██╔╝ ██╗╚██████╔╝██║  ██║   ██║   ██║ ╚████║
echo   ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝
echo.
echo   Ixoryn v1.0 — 
echo   Cross-Platform: Windows / macOS / Linux
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Download from https://python.org
    echo         Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo [OK] Python found
echo.
echo [*] Installing required packages...
echo.

pip install cryptography argon2-cffi PyNaCl bcrypt Pillow numpy scipy opencv-python stegano requests dnspython python-whois tld beautifulsoup4 sslyze hashid passlib zxcvbn scikit-learn weasyprint pdfkit colorama rich prompt_toolkit tabulate tqdm pyfiglet chardet python-magic filelock pytest

echo.
echo [*] Installing optional packages...
pip install pydub 2>nul || echo [SKIP] pydub (optional, for MP3/OGG audio)

echo.
echo ============================================================
echo   Ixoryn is ready!
echo.
echo   Launch with:   python ixoryn.py
echo.
echo   For hash cracking, install hashcat:
echo   https://hashcat.net/hashcat/
echo ============================================================
echo.
pause

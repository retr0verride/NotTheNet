@echo off
REM NotTheNet Windows Launcher — Batch script version
REM
REM Usage:
REM   launch.bat              - Start in GUI mode
REM   launch.bat headless     - Start in headless mode
REM   launch.bat headless DEBUG - Start headless with DEBUG logging

setlocal enabledelayedexpansion

cd /d "%~dp0"

echo.
echo [*] NotTheNet Windows Launcher
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found. Please install Python 3.10+
    echo [!] Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check dependencies
python -c "import dnslib, cryptography" >nul 2>&1
if errorlevel 1 (
    echo [!] Missing dependencies. Installing...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [!] Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Create logs directory
if not exist logs mkdir logs

REM Parse arguments
set "HEADLESS=0"
set "LOG_LEVEL=INFO"

if "%1"=="headless" (
    set "HEADLESS=1"
    if not "%2"=="" (
        set "LOG_LEVEL=%2"
    )
)

echo.
if %HEADLESS% equ 1 (
    echo [*] Starting in HEADLESS mode
    echo [i] Health endpoint: http://localhost:8080/health
    set "NTN_HEADLESS=1"
) else (
    echo [*] Starting in GUI mode
)

set "NTN_LOG_LEVEL=%LOG_LEVEL%"

echo.
python notthenet.py

echo [*] NotTheNet stopped
pause

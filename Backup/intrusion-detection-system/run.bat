@echo off
REM Hybrid IDS Windows Launcher
REM This script creates a virtual environment, installs dependencies, and runs the system

echo ================================================================
echo       Hybrid Intrusion Detection System - Windows Setup
echo ================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.10 or 3.11 from https://www.python.org/
    pause
    exit /b 1
)

echo [1/5] Checking Python version...
python --version

REM Check if virtual environment exists
if not exist "venv\" (
    echo.
    echo [2/5] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
) else (
    echo.
    echo [2/5] Virtual environment already exists
)

REM Activate virtual environment
echo.
echo [3/5] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo.
echo [4/5] Upgrading pip...
python -m pip install --upgrade pip --quiet

REM Install dependencies
echo.
echo [5/5] Installing dependencies (this may take a few minutes)...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    echo Please check requirements.txt and your internet connection
    pause
    exit /b 1
)

echo.
echo ================================================================
echo       Installation Complete!
echo ================================================================
echo.
echo Starting Hybrid IDS GUI...
echo.

REM Run the application
python run.py

REM Keep window open if there was an error
if errorlevel 1 (
    echo.
    echo Application exited with error
    pause
)

@echo off
REM Build Executable with PyInstaller
REM Requires: pip install pyinstaller

echo ================================================================
echo       Building Hybrid IDS Executable
echo ================================================================
echo.

REM Check if virtual environment is activated
python -c "import sys; sys.exit(0 if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) else 1)"
if errorlevel 1 (
    echo WARNING: Virtual environment not activated
    echo Please run: ..\venv\Scripts\activate
    pause
    exit /b 1
)

REM Clean previous builds
echo [1/4] Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

REM Run PyInstaller
echo.
echo [2/4] Running PyInstaller...
pyinstaller pyinstaller.spec --clean --noconfirm

if errorlevel 1 (
    echo.
    echo ERROR: PyInstaller build failed
    pause
    exit /b 1
)

REM Copy model files (if they exist)
echo.
echo [3/4] Copying model files...
if exist ..\models\*.keras (
    copy ..\models\*.keras dist\HybridIDS\models\
)
if exist ..\models\*.joblib (
    copy ..\models\*.joblib dist\HybridIDS\models\
)

REM Create README for distribution
echo.
echo [4/4] Creating distribution README...
(
echo Hybrid IDS - Standalone Distribution
echo =====================================
echo.
echo To run:
echo   1. Ensure Npcap is installed: https://npcap.com/
echo   2. Run HybridIDS.exe as Administrator for live capture
echo   3. Place model files in models/ directory
echo   4. Optional: Install Suricata for signature detection
echo.
echo For offline PCAP analysis, no admin rights needed.
echo.
echo Full documentation: See README.md in source distribution
) > dist\HybridIDS\README.txt

echo.
echo ================================================================
echo       Build Complete!
echo ================================================================
echo.
echo Executable: dist\HybridIDS\HybridIDS.exe
echo Size: 
dir dist\HybridIDS\HybridIDS.exe | find "HybridIDS.exe"
echo.
echo IMPORTANT NOTES:
echo - Model files must be in models/ directory next to EXE
echo - Total distribution size: ~500 MB due to TensorFlow
echo - Requires Npcap for packet capture
echo - Run as Administrator for live capture
echo.
pause

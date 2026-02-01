# Packaging Notes for Hybrid IDS

## Building Standalone Executable

### Prerequisites

1. **Virtual Environment Active**:
venv\Scripts\activate

2. **PyInstaller Installed**:
pip install pyinstaller

3. **All Dependencies Installed**:
pip install -r requirements.txt


### Build Process

cd packaging
build_exe.bat



This will:
1. Clean previous builds
2. Run PyInstaller with spec file
3. Copy model files to dist
4. Create distribution README

### Output

packaging/
dist/
HybridIDS/
HybridIDS.exe # Main executable (~100 MB)
models/ # Model files (must be present)
*.dll # Required DLLs
_internal/ # Python runtime and dependencies
README.txt



## Distribution Considerations

### Size

- **Executable alone**: ~100 MB
- **With TensorFlow dependencies**: ~400-500 MB
- **With models**: +100-500 MB (depending on model size)
- **Total distribution**: ~1 GB

### Optimization Options

#### Option 1: Separate Model Download
Don't bundle models with EXE. Provide download link:

HybridIDS_v1.0.zip (400 MB)
models_v1.0.zip (200 MB) - separate download



#### Option 2: UPX Compression
Already enabled in spec file. Reduces size by ~30%.

#### Option 3: Exclude Unused Libraries
Edit `pyinstaller.spec` to exclude:
- Unused TensorFlow ops
- Matplotlib (if not used)
- Jupyter components

### Runtime Requirements

**User's machine needs**:
1. Windows 10/11 (64-bit)
2. Npcap driver (for packet capture)
3. Visual C++ Redistributable 2015-2022
4. ~2 GB disk space
5. No Python installation needed

### Known Issues

1. **First Launch Slow**: TensorFlow initialization takes 10-30 seconds
2. **Antivirus False Positives**: Packed executables may trigger warnings
3. **Large Size**: Cannot significantly reduce below 300 MB due to TensorFlow
4. **Model Loading**: Models must be in `models/` relative to EXE

### Troubleshooting

**"Failed to execute script"**:
- Run from command line to see error
- Check logs in `%TEMP%`
- Ensure models directory exists

**"DLL not found"**:
- Install Visual C++ Redistributable
- Ensure all dependencies in _internal/

**High CPU on startup**:
- Normal - TensorFlow initialization
- Wait 30 seconds for first window

## Alternative Distribution Methods

### Method 1: Python Wheel
pip install build
python -m build



Distributes as `.whl` file. Users need Python.

### Method 2: MSI Installer
Use WiX Toolset to create professional installer:
- Installs to Program Files
- Creates Start Menu shortcuts
- Handles model downloads
- Checks prerequisites

### Method 3: Docker Container
FROM python:3.11-windowsservercore
COPY . /app
RUN pip install -r requirements.txt
CMD ["python", "run.py"]



Not ideal for Windows desktop use.

## Code Signing (Recommended for Production)

To avoid Windows SmartScreen warnings:

1. Obtain code signing certificate
2. Sign executable:
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com HybridIDS.exe



## Testing Distribution

Before release:

1. **Clean Machine Test**: Test on fresh Windows VM
2. **Without Python**: Ensure no Python dependency
3. **Without Admin**: Test offline mode
4. **With Admin**: Test live capture
5. **Model Loading**: Verify models load correctly
6. **Resource Usage**: Monitor CPU/RAM during operation

## Update Strategy

### Version 1.1 Update:
- Replace models in `models/` directory
- Update `HybridIDS.exe` 
- No reinstall needed (portable)

### Major Update:
- Full redistribution
- Consider MSI for upgrade path

---

**Build Date**: December 2025  
**Build System**: Windows 11, Python 3.11  
**PyInstaller Version**: 6.3.0
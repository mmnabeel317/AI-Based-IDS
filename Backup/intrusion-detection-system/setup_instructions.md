# Hybrid IDS - Detailed Setup Instructions

## System Requirements

### Hardware
- **CPU**: Intel Core i5 or AMD Ryzen 5 (or better)
- **RAM**: 8 GB minimum, 16 GB recommended
- **Disk**: 5 GB free space (10 GB if building from source)
- **Network**: Ethernet adapter for live capture (WiFi supported but may have limitations)

### Software
- **OS**: Windows 10 (64-bit, version 1909+) or Windows 11
- **Python**: 3.10 or 3.11 (3.12 may have compatibility issues with TensorFlow)
- **Npcap**: Version 1.70+ (required for packet capture)
- **Visual C++ Redistributable**: 2015-2022 (usually installed with Python)

### Optional
- **Suricata**: Version 6.0+ for signature-based detection
- **WSL2**: Windows Subsystem for Linux (if running Suricata on Linux)
- **CUDA Toolkit**: 11.8+ and cuDNN 8.6+ (for GPU acceleration)

---

## Step-by-Step Installation

### Step 1: Install Python

1. Download Python 3.10 or 3.11 from https://www.python.org/downloads/windows/
2. Run the installer
3. **Important**: Check "Add Python to PATH"
4. Choose "Install Now" or "Customize installation"
5. Verify installation:
python --version
pip --version



### Step 2: Install Npcap (Required for Packet Capture)

1. Download Npcap from https://npcap.com/#download
2. Run the installer **as Administrator**
3. Configuration options:
- ✅ Install Npcap in WinPcap API-compatible Mode (UNCHECKED - keep native mode)
- ✅ Support raw 802.11 traffic (CHECKED if using WiFi)
- ✅ Install Npcap Loopback Adapter (OPTIONAL)
4. Reboot if prompted

### Step 3: Extract the Project

cd C:\Users\YourName\Documents
unzip intrusion-detection-system.zip
cd intrusion-detection-system



### Step 4: Run Automated Setup

run.bat



This script will:
1. Create a Python virtual environment (`venv/`)
2. Install all dependencies from `requirements.txt`
3. Verify installations
4. Launch the GUI

**If you encounter errors**, proceed to manual installation:

### Step 5: Manual Installation (Alternative)

REM Create virtual environment
python -m venv venv

REM Activate it
venv\Scripts\activate

REM Upgrade pip
python -m pip install --upgrade pip

REM Install dependencies
pip install -r requirements.txt

REM Verify installation
python -c "import tensorflow as tf; print('TF version:', tf.version)"
python -c "import sklearn; print('sklearn version:', sklearn.version)"
python -c "from PyQt6.QtWidgets import QApplication; print('PyQt6 OK')"
python -c "import scapy.all; print('Scapy OK')"


### Step 6: Place Model Files

If you have pre-trained models:

copy attn_model.keras models
copy rf_model.joblib models
copy label_encoder.joblib models
copy feature_scaler.joblib models\



If models are missing, the system will use fallback synthetic models (for testing only).

### Step 7: (Optional) Install Suricata

#### Option A: Windows Native (Recommended)

1. Download Suricata MSI installer:
   - Visit https://suricata.io/download/
   - Download latest Windows build (e.g., `Suricata-7.0.0-windivert-1-64bit.msi`)

2. Install:
msiexec /i Suricata-7.0.0-windivert-1-64bit.msi /qb



3. Add to PATH:
setx PATH "%PATH%;C:\Program Files\Suricata"



4. Verify:
suricata --version



5. Update rules:
cd "C:\Program Files\Suricata"
suricata-update



6. Configure `utils/config.py`:
SURICATA_BINARY = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_EVE_JSON = r"C:\Program Files\Suricata\log\eve.json"



#### Option B: WSL (Windows Subsystem for Linux)

1. Install WSL2:
wsl --install -d Ubuntu



2. Open WSL terminal:
wsl



3. Install Suricata in WSL:
sudo apt update
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install suricata -y


4. Verify:
suricata --version



5. Update rules:
sudo suricata-update



6. Configure `utils/config.py` for WSL:
USE_WSL_SURICATA = True
WSL_SURICATA_PATH = "/usr/bin/suricata"
WSL_EVE_JSON = "/var/log/suricata/eve.json"



---

## Configuration

### Edit `utils/config.py`

Model ensemble weights
CNN_WEIGHT = 0.55
RF_WEIGHT = 0.45

Suricata paths
SURICATA_ENABLED = True # Set to False to disable
SURICATA_BINARY = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_EVE_JSON = r"C:\Program Files\Suricata\log\eve.json"

Flow parameters
FLOW_TIMEOUT = 120 # seconds
MAX_PACKETS_PER_FLOW = 10000

Logging
LOG_LEVEL = "INFO" # DEBUG, INFO, WARNING, ERROR
LOG_ROTATION_SIZE = 10 * 1024 * 1024 # 10 MB



---

## Running the System

### GUI Mode (Default)

run.bat



or

venv\Scripts\activate
python run.py



### Live Capture (Requires Admin)

REM Right-click Command Prompt -> "Run as Administrator"
venv\Scripts\activate
python run.py --mode live



### Offline PCAP Analysis

venv\Scripts\activate
python run.py --mode offline --pcap-path captures\sample.pcap



### CLI Mode (No GUI)

venv\Scripts\activate
python run.py --no-gui --mode live



### Debug Mode with Synthetic Data

venv\Scripts\activate
python run.py --mode debug



---

## Testing

### Run Self-Test

venv\Scripts\activate
python self_test.py



This will:
- Verify all dependencies
- Check model files
- Test feature extraction
- Test ML prediction pipeline
- Test Suricata integration
- Run end-to-end flow with synthetic data

### Run Unit Tests

venv\Scripts\activate
pytest -v



### Run Specific Test

pytest tests/test_predictor.py -v


### Generate Coverage Report

pytest --cov=. --cov-report=html



---

## GPU Acceleration (Optional)

To use GPU for faster inference:

### Step 1: Install CUDA Toolkit

1. Download CUDA 11.8 from https://developer.nvidia.com/cuda-11-8-0-download-archive
2. Install with default options
3. Verify:
nvcc --version



### Step 2: Install cuDNN

1. Download cuDNN 8.6 from https://developer.nvidia.com/cudnn
2. Extract and copy files:
copy cudnn-\bin*.dll "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8\bin"
copy cudnn-\include*.h "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8\include"
copy cudnn-*\lib\x64*.lib "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8\lib\x64"



### Step 3: Install TensorFlow-GPU

venv\Scripts\activate
pip uninstall tensorflow
pip install tensorflow[and-cuda]



### Step 4: Verify GPU

python -c "import tensorflow as tf; print('GPUs:', tf.config.list_physical_devices('GPU'))"


---

## Building Executable

To create a standalone EXE:

venv\Scripts\activate
cd packaging
build_exe.bat



Output: `packaging\dist\HybridIDS.exe`

**Note**: The EXE will be large (~500 MB) due to TensorFlow. Model files must be placed in `models/` next to the EXE.

---

## Troubleshooting

### Issue: "Python not found"
**Solution**: Add Python to PATH or reinstall with "Add to PATH" checked

### Issue: "No module named 'tensorflow'"
**Solution**: Activate virtual environment: `venv\Scripts\activate`

### Issue: "ImportError: DLL load failed"
**Solution**: Install Visual C++ Redistributable from https://aka.ms/vs/17/release/vc_redist.x64.exe

### Issue: "Npcap not found"
**Solution**: Reinstall Npcap and ensure it's in WinPcap-compatible mode for Scapy

### Issue: "Permission denied" during capture
**Solution**: Run terminal as Administrator

### Issue: "Suricata not found"
**Solution**: 
- Check PATH: `echo %PATH%`
- Verify installation: `suricata --version`
- Or disable Suricata: `python run.py --suricata-off`

### Issue: GUI window is blank
**Solution**:
- Update graphics drivers
- Try: `set QT_QPA_PLATFORM=windows`
- Check logs: `logs\app.log`

### Issue: High CPU usage
**Solution**:
- Reduce flow timeout in `utils/config.py`
- Limit packet capture count
- Disable GUI real-time updates (CLI mode)

### Issue: Models not loading
**Solution**:
- Verify files exist: `dir models\`
- Check file extensions: `.keras`, `.joblib`
- Check logs for specific error

---

## Updating

To update dependencies:

venv\Scripts\activate
pip install --upgrade -r requirements.txt



To update Suricata rules:

cd "C:\Program Files\Suricata"
suricata-update



---

## Uninstalling

rmdir /s /q venv
rmdir /s /q logs
rmdir /s /q pycache



To uninstall Suricata:
- Use "Add or Remove Programs" in Windows Settings

---

## Support

For issues:
1. Check `logs/app.log`
2. Run `python self_test.py`
3. Review this document
4. Check GitHub Issues (if applicable)

---

**Last Updated**: December 2025  
**Version**: 1.0.0
# Hybrid Intrusion Detection System (IDS)

A production-ready Windows-compatible Hybrid IDS combining Machine Learning (CNN + Random Forest ensemble) with traditional signature-based detection (Suricata integration).

## Features

- **Hybrid ML Detection**: CNN with Multi-Head Attention + Random Forest ensemble
- **Signature-Based IDS**: Suricata integration with eve.json parsing
- **Real-Time & Offline Modes**: Live packet capture or PCAP file analysis
- **Professional GUI**: PyQt6-based interface with real-time threat visualization
- **Production-Ready**: Full error handling, logging, testing, and packaging

## Quick Start

### Prerequisites

- Windows 10/11 (64-bit)
- Python 3.10 or 3.11
- Administrator privileges (for live packet capture only)
- Npcap driver installed (https://npcap.com/)
- (Optional) Suricata IDS for signature-based detection

### Installation

1. **Clone or extract the project**:
cd intrusion-detection-system



2. **Run the automated setup**:
run.bat



This will:
- Create a Python virtual environment
- Install all dependencies
- Verify the installation
- Launch the GUI

3. **Place trained models** (if available):
- `models/attn_model.keras` (CNN model)
- `models/rf_model.joblib` (Random Forest)
- `models/label_encoder.joblib` (Label encoder)
- `models/feature_scaler.joblib` (Feature scaler)

*Note: If models are missing, the system will use fallback synthetic models for testing.*

### Running the System

**GUI Mode (Recommended)**:
run.bat


**CLI Mode**:
venv\Scripts\activate
python run.py --mode live



**Offline PCAP Analysis**:
python run.py --mode offline --pcap-path path\to\capture.pcap



**Self-Test**:
python self_test.py



## Architecture

The system uses a three-layer architecture:

1. **Capture Layer**: Scapy-based packet capture and flow aggregation
2. **Detection Layer**: 
   - ML Ensemble (CNN + RF) for behavioral analysis
   - Suricata for signature matching
3. **Fusion Layer**: Decision engine combining ML and signature results
4. **Presentation Layer**: PyQt6 GUI with real-time alerts

See `README_ARCHITECTURE.md` for detailed technical documentation.

## Configuration

Edit `utils/config.py` to customize:
- Model weights (CNN vs RF balance)
- Suricata paths and rule files
- Flow timeout parameters
- Alert thresholds
- Logging levels

## Testing

Run all tests:
venv\Scripts\activate
pytest -v



Run self-test:
python self_test.py



## Building Executable

To create a standalone EXE:
cd packaging
build_exe.bat



The executable will be in `packaging/dist/`.

## Suricata Integration

### Windows Native Installation

1. Download Suricata MSI installer from https://suricata.io/download/
2. Install to default location: `C:\Program Files\Suricata`
3. Install Npcap with WinPcap compatibility mode OFF
4. Update rule path in `utils/config.py`

### WSL (Windows Subsystem for Linux) Alternative

If Suricata is not available natively:
wsl --install -d Ubuntu
wsl
sudo apt update && sudo apt install suricata -y



The system automatically detects WSL and adjusts paths.

## Troubleshooting

### "Permission denied" during packet capture
- Run terminal as Administrator
- Or use offline mode with PCAP files

### "No module named 'tensorflow'"
- Ensure virtual environment is activated: `venv\Scripts\activate`
- Reinstall: `pip install -r requirements.txt`

### Suricata not found
- Check installation path in `utils/config.py`
- Verify Suricata is in system PATH
- Use WSL installation as fallback

### GUI doesn't start
- Update graphics drivers
- Install Visual C++ Redistributables
- Check logs in `logs/app.log`

## Contributing

This is a production system. For modifications:
1. Write tests first (see `tests/` directory)
2. Follow PEP 8 style guidelines
3. Update documentation
4. Run full test suite before committing

## License

MIT License - see LICENSE file for details.

## Support

For issues, check:
- `logs/app.log` for runtime errors
- `setup_instructions.md` for detailed setup
- Run `self_test.py` for diagnostic information


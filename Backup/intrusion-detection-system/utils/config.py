"""
Configuration Module
Central configuration for the Hybrid IDS.
"""

from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
MODELS_PATH = PROJECT_ROOT / 'models'
LOGS_PATH = PROJECT_ROOT / 'logs'
DATA_PATH = PROJECT_ROOT / 'data'

# Model ensemble weights
CNN_WEIGHT = 0.55
RF_WEIGHT = 0.45

# Suricata configuration
SURICATA_ENABLED = True
USE_WSL_SURICATA = True  # Set to True if using Suricata in WSL

# Windows paths
SURICATA_BINARY = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_EVE_JSON = r"C:\Program Files\Suricata\log\eve.json"
SURICATA_CONFIG = r"C:\Program Files\Suricata\suricata.yaml"

# WSL paths (if USE_WSL_SURICATA = True)
WSL_DISTRIBUTION = "Ubuntu"
WSL_SURICATA_BINARY = "/usr/bin/suricata"
WSL_EVE_JSON = "/var/log/suricata/eve.json"
WSL_SURICATA_CONFIG = "/etc/suricata/suricata.yaml"

# Flow builder configuration
FLOW_TIMEOUT = 120  # seconds
MAX_PACKETS_PER_FLOW = 10000

# Decision thresholds
HIGH_CONFIDENCE_THRESHOLD = 0.85
MEDIUM_CONFIDENCE_THRESHOLD = 0.65
LOW_CONFIDENCE_THRESHOLD = 0.45

# Logging configuration
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_ROTATION_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Network capture configuration
DEFAULT_INTERFACE = None  # Auto-detect if None
CAPTURE_FILTER = ""  # BPF filter (empty = capture all)
CAPTURE_TIMEOUT = 30  # seconds

# GUI configuration
GUI_UPDATE_INTERVAL = 1000  # milliseconds
MAX_TABLE_ROWS = 1000  # Maximum rows in GUI table before auto-clear

# Feature extraction
FEATURE_COUNT = 67

# Classes
ATTACK_CLASSES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']


class Config:
    """Dynamic configuration class."""
    
    def __init__(self):
        """Initialize configuration."""
        self.load_defaults()
    
    def load_defaults(self):
        """Load default configuration."""
        self.MODELS_PATH = MODELS_PATH
        self.CNN_WEIGHT = CNN_WEIGHT
        self.RF_WEIGHT = RF_WEIGHT
        self.SURICATA_ENABLED = SURICATA_ENABLED
        self.FLOW_TIMEOUT = FLOW_TIMEOUT
        
    def update(self, **kwargs):
        """Update configuration values."""
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self) -> dict:
        """Export configuration to dictionary."""
        return {
            k: v for k, v in self.__dict__.items()
            if not k.startswith('_')
        }


# Global config instance
config = Config()

"""
Label Mapping Module
Maps attack labels to human-readable descriptions.
"""

from typing import Dict

# Your actual class labels (0-8)
CLASS_LABELS: Dict[str, str] = {
    '0': 'Benign',
    '1': 'Bot',
    '2': 'DDOS attack-HOIC',
    '3': 'DoS attacks-GoldenEye',
    '4': 'DoS attacks-Hulk',
    '5': 'DoS attacks-SlowHTTPTest',
    '6': 'FTP-BruteForce',
    '7': 'Infilteration',
    '8': 'SSH-Bruteforce'
}

# Attack class descriptions
LABEL_DESCRIPTIONS: Dict[str, str] = {
    '0': 'Legitimate network traffic with no detected anomalies',
    '1': 'Botnet activity - infected hosts communicating with C&C servers',
    '2': 'Distributed Denial of Service using High Orbit Ion Cannon tool',
    '3': 'DoS attack using GoldenEye tool targeting web applications',
    '4': 'DoS attack using Hulk tool generating unique HTTP requests',
    '5': 'Slow HTTP DoS attack exhausting server connections',
    '6': 'Brute force attack attempting FTP credential compromise',
    '7': 'Infiltration attempt - unauthorized access from inside network',
    '8': 'SSH brute force attack attempting credential compromise'
}

# Severity levels
LABEL_SEVERITY: Dict[str, int] = {
    '0': 0,  # Benign
    '1': 3,  # Bot
    '2': 3,  # DDOS
    '3': 3,  # DoS GoldenEye
    '4': 3,  # DoS Hulk
    '5': 3,  # DoS SlowHTTP
    '6': 2,  # FTP Brute
    '7': 3,  # Infiltration
    '8': 2   # SSH Brute
}

# Color coding for GUI
LABEL_COLORS: Dict[str, str] = {
    '0': '#28a745',   # Green - Benign
    '1': '#dc3545',   # Red - Bot
    '2': '#dc3545',   # Red - DDOS
    '3': '#dc3545',   # Red - DoS GoldenEye
    '4': '#dc3545',   # Red - DoS Hulk
    '5': '#fd7e14',   # Orange - DoS SlowHTTP
    '6': '#ffc107',   # Yellow - FTP Brute
    '7': '#dc3545',   # Red - Infiltration
    '8': '#ffc107'    # Yellow - SSH Brute
}


def get_label_name(label_id: str) -> str:
    """Get human-readable name for label ID."""
    return CLASS_LABELS.get(str(label_id), f'Unknown-{label_id}')


def get_label_info(label: str) -> Dict:
    """
    Get comprehensive information about a label.
    
    Args:
        label: Attack class label (as string, e.g., '0', '7')
        
    Returns:
        Dictionary with description, severity, and color
    """
    label_str = str(label)
    return {
        'label': label_str,
        'name': CLASS_LABELS.get(label_str, f'Unknown-{label}'),
        'description': LABEL_DESCRIPTIONS.get(label_str, 'Unknown attack type'),
        'severity': LABEL_SEVERITY.get(label_str, 0),
        'color': LABEL_COLORS.get(label_str, '#6c757d')
    }

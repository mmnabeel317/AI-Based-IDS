"""
Qt Resources Module
Icons, styles, and other GUI resources.
"""

# Color scheme for threat levels
COLORS = {
    'normal': '#28a745',      # Green
    'low': '#ffc107',         # Yellow
    'medium': '#fd7e14',      # Orange
    'high': '#dc3545',        # Red
    'critical': '#6f1c1c',    # Dark Red
    'error': '#6c757d'        # Gray
}

# Stylesheet for the application
STYLESHEET = """
QMainWindow {
    background-color: #f5f5f5;
}

QGroupBox {
    font-weight: bold;
    border: 2px solid #cccccc;
    border-radius: 5px;
    margin-top: 10px;
    padding-top: 10px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px 0 5px;
}

QPushButton {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #0056b3;
}

QPushButton:pressed {
    background-color: #004085;
}

QPushButton:disabled {
    background-color: #6c757d;
}

QTableWidget {
    border: 1px solid #dee2e6;
    border-radius: 4px;
    background-color: white;
}

QTableWidget::item {
    padding: 5px;
}

QTableWidget::item:selected {
    background-color: #007bff;
    color: white;
}

QHeaderView::section {
    background-color: #343a40;
    color: white;
    padding: 8px;
    border: none;
    font-weight: bold;
}

QStatusBar {
    background-color: #343a40;
    color: white;
}

QLabel {
    color: #333333;
}
"""


def get_threat_color(alert_level: str) -> str:
    """Get color for threat level."""
    return COLORS.get(alert_level.lower(), COLORS['error'])


def get_label_color(label: str) -> str:
    """Get color for classification label."""
    label_colors = {
        'Normal': COLORS['normal'],
        'DoS': COLORS['critical'],
        'Probe': COLORS['medium'],
        'R2L': COLORS['high'],
        'U2R': COLORS['high']
    }
    return label_colors.get(label, COLORS['error'])

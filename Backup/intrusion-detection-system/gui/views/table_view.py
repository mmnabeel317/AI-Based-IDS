"""
Flow Table View
Displays detected flows with color-coded threat levels.
"""

import logging
import csv
import json
from typing import List, Dict
from datetime import datetime

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView 
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtGui import QIcon, QFont

from gui.qt_resources import get_threat_color, get_label_color

logger = logging.getLogger(__name__)


def clear_flows(self):
    """Clear all flows from table."""
    self.flows.clear()
    self.setRowCount(0)


class FlowTableView(QTableWidget):
    """Table widget for displaying flow analysis results."""
    
    COLUMNS = [
        'Timestamp',
        'Source IP',
        'Dest IP',
        'Ports',
        'Protocol',
        'Classification',
        'Confidence',
        'Alert Level',
        'CNN',
        'RF',
        'Suricata'
    ]
    
    def __init__(self):
        """Initialize table view."""
        super().__init__()
        
        self.flows: List[Dict] = []
        
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        
        # Configure table
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(True)
        
        # Resize columns
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        
        logger.info("Flow table view initialized")
    
    def add_flow(self, result: dict):
        """Add flow result to table."""
        try:
            row = self.rowCount()
            self.insertRow(row)
            
            # Get flow info
            flow_info = result.get('flow_info', {})
            timestamp = result.get('timestamp', datetime.now().isoformat())
            
            # Parse timestamp
            if isinstance(timestamp, str):
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime('%H:%M:%S')
                except:
                    time_str = timestamp[:8] if len(timestamp) >= 8 else timestamp
            else:
                time_str = datetime.now().strftime('%H:%M:%S')
            
            # Get classification from final_label
            final_label = result.get('final_label', '0')
            final_confidence = result.get('final_confidence', 0.0)
            
            # Get label name
            from inference.label_mapping import get_label_name
            classification = get_label_name(final_label)
            
            # Get alert level
            alert_level = result.get('alert_level', 'info')
            
            # Get model predictions
            models = result.get('models', {})
            cnn_pred = models.get('cnn', {})
            rf_pred = models.get('rf', {})
            
            cnn_class = str(cnn_pred.get('predicted_class', '0'))
            cnn_conf = cnn_pred.get('confidence', 0.0)
            rf_class = str(rf_pred.get('predicted_class', '0'))
            rf_conf = rf_pred.get('confidence', 0.0)
            
            # Format model display
            cnn_label = get_label_name(cnn_class)
            rf_label = get_label_name(rf_class)
            cnn_display = f"{cnn_label} ({cnn_class})"
            rf_display = f"{rf_label} ({rf_class})"
            
            # Get Suricata info
            suricata_alert = result.get('suricata_alert')
            suricata_text = "None"
            if suricata_alert and suricata_alert.get('alert'):
                suricata_text = suricata_alert.get('signature', 'Alert')
            
            # Set table items
            self.setItem(row, 0, QTableWidgetItem(time_str))
            self.setItem(row, 1, QTableWidgetItem(str(flow_info.get('src_ip', 'unknown'))))
            self.setItem(row, 2, QTableWidgetItem(str(flow_info.get('dst_ip', 'unknown'))))
            
            # Ports
            src_port = flow_info.get('src_port', 0)
            dst_port = flow_info.get('dst_port', 0)
            self.setItem(row, 3, QTableWidgetItem(f"{src_port}→{dst_port}"))
            
            # Protocol
            protocol = flow_info.get('protocol', 6)
            protocol_name = 'TCP' if protocol == 6 else 'UDP' if protocol == 17 else 'ICMP' if protocol == 1 else str(protocol)
            self.setItem(row, 4, QTableWidgetItem(protocol_name))
            
            # Classification
            classification_item = QTableWidgetItem(classification)
            if final_label != '0':  # Not benign
                classification_item.setForeground(QColor('#dc3545'))
                classification_item.setFont(QFont('Segoe UI', 9, QFont.Weight.Bold))
            else:
                classification_item.setForeground(QColor('#28a745'))
            self.setItem(row, 5, classification_item)
            
            # Confidence
            confidence_item = QTableWidgetItem(f"{final_confidence:.1%}")
            self.setItem(row, 6, confidence_item)
            
            # Alert Level
            alert_item = QTableWidgetItem(alert_level.upper())
            alert_colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#17a2b8',
                'info': '#6c757d'
            }
            alert_item.setBackground(QColor(alert_colors.get(alert_level, '#6c757d')))
            alert_item.setForeground(QColor('white'))
            alert_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setItem(row, 7, alert_item)
            
            # CNN prediction
            self.setItem(row, 8, QTableWidgetItem(cnn_display))
            
            # RF prediction
            self.setItem(row, 9, QTableWidgetItem(rf_display))
            
            # Suricata
            self.setItem(row, 10, QTableWidgetItem(suricata_text))
            
            # Store full result
            self.flows.append(result)
            
            # Auto-scroll to new row
            self.scrollToBottom()
            
            # Update stats
            self._update_stats()
            
        except Exception as e:
            logger.error(f"Failed to add flow to table: {e}", exc_info=True)

    def _update_stats(self):
        """Update flow statistics."""
        total = len(self.flows)
        
        # Count by classification
        benign = sum(1 for f in self.flows if f.get('final_label') == '0')
        attacks = total - benign
        
        # Count by alert level
        critical = sum(1 for f in self.flows if f.get('alert_level') == 'critical')
        high = sum(1 for f in self.flows if f.get('alert_level') == 'high')
        
        logger.debug(f"Stats: {total} flows, {benign} benign, {attacks} attacks, {critical} critical, {high} high")

    
    def _protocol_to_string(self, protocol: int) -> str:
        """Convert protocol number to string."""
        protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        return protocol_map.get(protocol, str(protocol))
    
    def clear(self):
        """Clear all rows."""
        self.setRowCount(0)
        self.flows.clear()
        logger.info("Table cleared")
    
    def get_stats(self) -> Dict:
        """Get table statistics."""
        threat_count = sum(
            1 for flow in self.flows
            if flow.get('final_label') != 'Normal'
        )
        
        return {
            'total_flows': len(self.flows),
            'threat_count': threat_count
        }
    
    def export_to_csv(self, filepath: str):
        """
        Export table data to CSV.
        
        Args:
            filepath: Output file path
        """
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(self.COLUMNS)
            
            # Write rows
            for row in range(self.rowCount()):
                row_data = []
                for col in range(self.columnCount()):
                    item = self.item(row, col)
                    row_data.append(item.text() if item else '')
                writer.writerow(row_data)
        
        logger.info(f"Exported {self.rowCount()} rows to CSV: {filepath}")
    
    def export_to_json(self, filepath: str):
        """
        Export flow data to JSON.
        
        Args:
            filepath: Output file path
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.flows, f, indent=2)
        
        logger.info(f"Exported {len(self.flows)} flows to JSON: {filepath}")

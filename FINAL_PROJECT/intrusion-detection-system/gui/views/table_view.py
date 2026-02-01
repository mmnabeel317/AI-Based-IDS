"""
Flow Table View - Displays detected flows with classifications
"""

from PyQt6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, 
    QAbstractItemView, QMenu
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush
from utils.logger import get_logger

logger = get_logger(__name__)


class FlowTableView(QTableWidget):
    """Table widget for displaying network flows"""
    
    # Signal emitted when a flow is selected
    flow_selected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.flows_data = []
        self._setup_table()
        logger.info("Flow table view initialized")
    
    def _setup_table(self):
        """Setup table columns and properties"""
        # Define columns
        self.columns = [
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
        
        self.setColumnCount(len(self.columns))
        self.setHorizontalHeaderLabels(self.columns)
        
        # Table properties
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(True)
        
        # Column widths
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Timestamp
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # Source IP
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Dest IP
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Ports
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)  # Classification
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Confidence
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)  # Alert Level
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)  # CNN
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.ResizeToContents)  # RF
        header.setSectionResizeMode(10, QHeaderView.ResizeMode.ResizeToContents)  # Suricata
        
        # Style
        self.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                gridline-color: #3a3a3a;
                selection-background-color: #0d47a1;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #1e1e1e;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #3a3a3a;
                font-weight: bold;
            }
        """)
        
        # Connect selection signal
        self.itemSelectionChanged.connect(self._on_selection_changed)
        
        # Context menu
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
    
    def add_flow(self, flow, prediction, suricata_result=None):
        """
        Add a flow to the table with prediction results.
        
        Args:
            flow (dict): Flow data
            prediction (dict): Prediction result from HybridPredictor
            suricata_result (dict): Optional Suricata detection result
        """
        try:
            # Store flow data
            self.flows_data.append({
                'flow': flow,
                'prediction': prediction,
                'suricata': suricata_result
            })
            
            # Insert new row
            row = self.rowCount()
            self.insertRow(row)
            
            # Column 0: Timestamp
            timestamp = flow.get('flow_start_time', 0)
            timestamp_str = self._format_timestamp(timestamp)
            self.setItem(row, 0, self._create_item(timestamp_str))
            
            # Column 1: Source IP
            src_ip = flow.get('src_ip', 'N/A')
            self.setItem(row, 1, self._create_item(src_ip))
            
            # Column 2: Dest IP
            dst_ip = flow.get('dst_ip', 'N/A')
            self.setItem(row, 2, self._create_item(dst_ip))
            
            # Column 3: Ports
            src_port = flow.get('src_port', 0)
            dst_port = flow.get('dst_port', 0)
            ports = f"{src_port}→{dst_port}"
            self.setItem(row, 3, self._create_item(ports))
            
            # Column 4: Protocol
            protocol = flow.get('protocol', 'N/A')
            self.setItem(row, 4, self._create_item(protocol))
            
            # Column 5: Classification (from prediction)
            if prediction and 'class_name' in prediction:
                classification = prediction['class_name']
            else:
                classification = 'Unknown'
            
            classification_item = self._create_item(classification)
            classification_item = self._color_by_classification(classification_item, classification)
            self.setItem(row, 5, classification_item)
            
            # Column 6: Confidence
            if prediction and 'confidence' in prediction:
                confidence = prediction['confidence']
                confidence_str = f"{confidence:.1%}"
            else:
                confidence = 0.0
                confidence_str = "0.0%"
            
            confidence_item = self._create_item(confidence_str)
            confidence_item.setData(Qt.ItemDataRole.UserRole, confidence)  # Store numeric value
            self.setItem(row, 6, confidence_item)
            
            # Column 7: Alert Level
            alert_level = self._get_alert_level(classification)
            alert_item = self._create_item(alert_level)
            alert_item = self._color_by_alert_level(alert_item, alert_level)
            self.setItem(row, 7, alert_item)
            
            # Column 8: CNN Result
            cnn_class = 'N/A'
            if prediction:
                if 'class_name' in prediction:
                    cnn_class = prediction['class_name']
                cnn_conf = prediction.get('confidence', 0.0)
                cnn_text = f"{cnn_class[:20]} ({cnn_conf:.0%})"
            else:
                cnn_text = 'N/A'
            self.setItem(row, 8, self._create_item(cnn_text))
            
            # Column 9: RF Result
            rf_text = 'N/A'
            if prediction and 'rf_class' in prediction:
                rf_class = prediction['rf_class']
                rf_conf = prediction.get('rf_confidence', 0.0)
                rf_text = f"{rf_class[:20]} ({rf_conf:.0%})"
            elif prediction and prediction.get('method') == 'cnn_only':
                rf_text = 'None'
            self.setItem(row, 9, self._create_item(rf_text))
            
            # Column 10: Suricata Result
            if suricata_result and suricata_result.get('alert'):
                suricata_text = suricata_result.get('signature', 'Alert')
                suricata_item = self._create_item(suricata_text)
                suricata_item.setBackground(QBrush(QColor(255, 100, 100, 100)))
            else:
                suricata_text = 'None'
                suricata_item = self._create_item(suricata_text)
            self.setItem(row, 10, suricata_item)
            
            # Scroll to new row
            self.scrollToBottom()
            
        except Exception as e:
            logger.error(f"Failed to add flow to table: {e}")
            import traceback
            traceback.print_exc()
    
    def _create_item(self, text):
        """Create a table item with text"""
        item = QTableWidgetItem(str(text))
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        return item
    
    def _format_timestamp(self, timestamp):
        """Format timestamp for display"""
        try:
            from datetime import datetime
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%H:%M:%S")
        except:
            return "N/A"
    
    def _get_alert_level(self, classification):
        """Get alert level based on classification"""
        if classification == 'Benign':
            return 'INFO'
        elif 'DDoS' in classification or 'DoS' in classification:
            return 'CRITICAL'
        elif 'Brute' in classification or 'Bot' in classification:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _color_by_classification(self, item, classification):
        """Color item based on classification"""
        if classification == 'Benign':
            color = QColor(100, 200, 100)  # Green
        elif 'DDoS' in classification or 'DoS' in classification:
            color = QColor(255, 100, 100)  # Red
        elif 'Brute' in classification:
            color = QColor(255, 165, 0)  # Orange
        elif 'Bot' in classification:
            color = QColor(255, 200, 0)  # Yellow
        else:
            color = QColor(200, 200, 100)  # Light yellow
        
        item.setForeground(QBrush(color))
        return item
    
    def _color_by_alert_level(self, item, level):
        """Color item based on alert level"""
        colors = {
            'INFO': QColor(150, 150, 150),
            'MEDIUM': QColor(255, 200, 0),
            'HIGH': QColor(255, 165, 0),
            'CRITICAL': QColor(255, 100, 100)
        }
        color = colors.get(level, QColor(200, 200, 200))
        item.setForeground(QBrush(color))
        return item
    
    def _on_selection_changed(self):
        """Handle row selection"""
        selected_rows = self.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            if row < len(self.flows_data):
                flow_data = self.flows_data[row]
                self.flow_selected.emit(flow_data)
    
    def _show_context_menu(self, position):
        """Show context menu"""
        menu = QMenu()
        
        copy_action = menu.addAction("Copy")
        details_action = menu.addAction("Show Details")
        export_action = menu.addAction("Export Flow")
        
        action = menu.exec(self.viewport().mapToGlobal(position))
        
        if action == copy_action:
            self._copy_selected()
        elif action == details_action:
            self._show_details()
        elif action == export_action:
            self._export_flow()
    
    def _copy_selected(self):
        """Copy selected row to clipboard"""
        selected_rows = self.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            text_parts = []
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    text_parts.append(item.text())
            
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText('\t'.join(text_parts))
            logger.info("Copied row to clipboard")
    
    def _show_details(self):
        """Show detailed information about selected flow"""
        selected_rows = self.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            if row < len(self.flows_data):
                flow_data = self.flows_data[row]
                logger.info(f"Flow details: {flow_data}")
                # TODO: Show details dialog
    
    def _export_flow(self):
        """Export flow data"""
        selected_rows = self.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            if row < len(self.flows_data):
                # TODO: Implement export functionality
                logger.info(f"Export flow {row}")
    
    def clear_flows(self):
        """Clear all flows from table"""
        self.setRowCount(0)
        self.flows_data.clear()
        logger.info("Cleared all flows from table")
    
    def get_flow_count(self):
        """Get total number of flows"""
        return self.rowCount()
    
    def get_alert_count(self):
        """Get count of flows by alert level"""
        counts = {
            'INFO': 0,
            'MEDIUM': 0,
            'HIGH': 0,
            'CRITICAL': 0
        }
        
        for i in range(self.rowCount()):
            item = self.item(i, 7)  # Alert Level column
            if item:
                level = item.text()
                if level in counts:
                    counts[level] += 1
        
        return counts
    
    def get_classification_counts(self):
        """Get count of flows by classification"""
        counts = {}
        
        for i in range(self.rowCount()):
            item = self.item(i, 5)  # Classification column
            if item:
                classification = item.text()
                counts[classification] = counts.get(classification, 0) + 1
        
        return counts
    
    def filter_by_classification(self, classification):
        """Show only flows matching classification"""
        for i in range(self.rowCount()):
            item = self.item(i, 5)
            if item:
                if classification == "All" or item.text() == classification:
                    self.setRowHidden(i, False)
                else:
                    self.setRowHidden(i, True)
    
    def filter_by_alert_level(self, level):
        """Show only flows matching alert level"""
        for i in range(self.rowCount()):
            item = self.item(i, 7)
            if item:
                if level == "All" or item.text() == level:
                    self.setRowHidden(i, False)
                else:
                    self.setRowHidden(i, True)
    
    def export_to_csv(self, filename):
        """Export table data to CSV file"""
        try:
            import csv
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write headers
                headers = [self.horizontalHeaderItem(i).text() 
                          for i in range(self.columnCount())]
                writer.writerow(headers)
                
                # Write rows
                for row in range(self.rowCount()):
                    row_data = []
                    for col in range(self.columnCount()):
                        item = self.item(row, col)
                        row_data.append(item.text() if item else '')
                    writer.writerow(row_data)
            
            logger.info(f"Exported {self.rowCount()} flows to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            return False


# Test function
if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    import sys
    
    app = QApplication(sys.argv)
    
    table = FlowTableView()
    table.resize(1200, 600)
    table.show()
    
    # Add test data
    test_flow = {
        'flow_start_time': 1733445600.0,
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 443,
        'protocol': 'TCP'
    }
    
    test_prediction = {
        'class_index': 0,
        'class_name': 'Benign',
        'confidence': 0.85,
        'method': 'hybrid_agree',
        'rf_class': 'Benign',
        'rf_confidence': 0.80
    }
    
    table.add_flow(test_flow, test_prediction)
    
    # Add attack example
    test_flow2 = {
        'flow_start_time': 1733445601.0,
        'src_ip': '10.0.0.5',
        'dst_ip': '192.168.1.100',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP'
    }
    
    test_prediction2 = {
        'class_index': 7,
        'class_name': 'DoS attacks-Hulk',
        'confidence': 0.92,
        'method': 'hybrid_agree',
        'rf_class': 'DoS attacks-Hulk',
        'rf_confidence': 0.88
    }
    
    table.add_flow(test_flow2, test_prediction2)
    
    print(f"Flows: {table.get_flow_count()}")
    print(f"Alerts: {table.get_alert_count()}")
    print(f"Classifications: {table.get_classification_counts()}")
    
    sys.exit(app.exec())

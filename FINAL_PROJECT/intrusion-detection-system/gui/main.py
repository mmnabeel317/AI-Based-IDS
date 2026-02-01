"""
Main GUI Application
PyQt6-based graphical interface for Hybrid IDS.
"""
from PyQt6.QtCore import QTimer, pyqtSignal, QObject, pyqtSlot, QMetaObject, Qt as QtCore

import logging
import sys
from pathlib import Path
from typing import Optional
import threading
import time

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStatusBar, QMessageBox,
    QFileDialog, QGroupBox, QTextEdit
)
from PyQt6.QtCore import QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QIcon, QFont

from gui.views.table_view import FlowTableView
from gui.controllers.capture_controller import CaptureController

"""
Main GUI Module
Provides the primary application window and user interface.
"""

import sys
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict
import threading

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStatusBar, QMenuBar,
    QMenu, QMessageBox, QFileDialog, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, pyqtSlot
from PyQt6.QtGui import QAction, QIcon

from gui.views.table_view import FlowTableView
from gui.controllers.capture_controller import CaptureController
from inference.predictor import HybridPredictor
from utils.config import PROJECT_ROOT

logger = logging.getLogger(__name__)


# Signal class for thread-safe communication
class FlowSignals(QObject):
    """Signals for thread-safe flow detection."""
    flow_detected = pyqtSignal(dict)
    analysis_complete = pyqtSignal(int)  # Total flows analyzed
    error = pyqtSignal(str)
    status_update = pyqtSignal(str)

logger = logging.getLogger(__name__)


class WorkerSignals(QObject):
    """Signals for worker threads."""
    flow_detected = pyqtSignal(dict)
    error = pyqtSignal(str)
    finished = pyqtSignal()



class IDSApplication(QMainWindow):
    """Main IDS application window."""
    
    def __init__(self, mode: str = 'live', pcap_path: Optional[Path] = None,
                 models_path: Path = None, suricata_enabled: bool = True,
                 interface: Optional[str] = None):
        super().__init__()
        
        self.mode = mode
        self.pcap_path = pcap_path
        self.models_path = models_path or PROJECT_ROOT / 'models'
        self.suricata_enabled = suricata_enabled
        self.interface = interface
        
        # Capture state
        self.capture_active = False
        self.capture_thread = None
        
        # Create signals for thread-safe communication
        self.signals = FlowSignals()
        self.signals.flow_detected.connect(self.on_flow_detected)
        self.signals.analysis_complete.connect(self.on_analysis_complete)
        self.signals.error.connect(self.on_error)
        self.signals.status_update.connect(self.on_status_update)
        
        # Initialize controller
        logger.info("Initializing Hybrid Predictor...")
        predictor = HybridPredictor(models_path=self.models_path)
        
        self.controller = CaptureController(
            predictor=predictor,
            suricata_enabled=suricata_enabled
        )
        
        # Setup UI
        self.setup_ui()
        
        # Auto-start based on mode
        if self.mode == 'offline' and self.pcap_path:
            # Delay to let GUI render first
            QTimer.singleShot(500, self.start_offline_analysis)
        elif self.mode == 'debug':
            QTimer.singleShot(500, self.start_debug_mode)
        
        logger.info("GUI initialized")
    
    def setup_ui(self):
        """Setup the user interface."""
        self.setWindowTitle("Hybrid Intrusion Detection System")
        self.setMinimumSize(1400, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create header
        header_layout = QHBoxLayout()
        
        # Title
        title_label = QLabel("🛡️ Hybrid IDS")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Mode indicator
        mode_label = QLabel(f"Mode: {self.mode.upper()}")
        mode_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #7f8c8d;
                padding: 10px;
            }
        """)
        header_layout.addWidget(mode_label)
        
        main_layout.addLayout(header_layout)
        
        # Create control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Create flow table
        self.flow_table = FlowTableView()
        main_layout.addWidget(self.flow_table)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        logger.info("GUI initialized")

    def create_menu_bar(self):
        """Create application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        # Open PCAP action
        open_action = QAction("&Open PCAP...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_pcap_file)
        file_menu.addAction(open_action)
        
        # Export action
        export_action = QAction("&Export Results...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        # Clear action
        clear_action = QAction("&Clear Results", self)
        clear_action.triggered.connect(self.clear_results)
        view_menu.addAction(clear_action)
        
        # Refresh action
        refresh_action = QAction("&Refresh", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_view)
        view_menu.addAction(refresh_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        # About action
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_control_panel(self) -> QWidget:
        """
        Create control panel with start/stop buttons.
        
        Returns:
            QWidget containing control panel
        """
        panel = QWidget()
        panel.setStyleSheet("""
            QWidget {
                background-color: #ecf0f1;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        
        layout = QHBoxLayout(panel)
        
        # Start/Stop button
        self.start_stop_btn = QPushButton("▶ Start Capture")
        self.start_stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-size: 16px;
                font-weight: bold;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:pressed {
                background-color: #1e8449;
            }
        """)
        self.start_stop_btn.clicked.connect(self.toggle_capture)
        layout.addWidget(self.start_stop_btn)
        
        # Info label
        info_label = QLabel(f"Interface: {self.interface or 'Auto-detect'}")
        info_label.setStyleSheet("color: #34495e; font-size: 12px;")
        layout.addWidget(info_label)
        
        layout.addStretch()
        
        # Statistics labels
        self.stats_label = QLabel("Flows: 0 | Alerts: 0")
        self.stats_label.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        layout.addWidget(self.stats_label)
        
        return panel

    def toggle_capture(self):
        """Toggle between start and stop capture."""
        if self.capture_active:
            self.stop_capture()
        else:
            if self.mode == 'live':
                self.start_live_capture()
            elif self.mode == 'offline':
                self.start_offline_analysis()
            elif self.mode == 'debug':
                self.start_debug_mode()

    def stop_capture(self):
        """Stop ongoing capture."""
        logger.info("Stopping capture...")
        self.capture_active = False
        self.controller.stop_capture()
        self.start_stop_btn.setText("▶ Start Capture")
        self.status_bar.showMessage("Capture stopped", 3000)

    def open_pcap_file(self):
        """Open PCAP file dialog."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            str(Path.home()),
            "PCAP Files (*.pcap *.pcapng);;All Files (*.*)"
        )
        
        if file_path:
            self.pcap_path = Path(file_path)
            self.mode = 'offline'
            self.clear_results()
            self.start_offline_analysis()

    def export_results(self):
        """Export results to CSV."""
        if self.flow_table.rowCount() == 0:
            QMessageBox.warning(
                self,
                "No Data",
                "No flows to export. Capture some traffic first."
            )
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            str(Path.home() / "ids_results.csv"),
            "CSV Files (*.csv);;All Files (*.*)"
        )
        
        if file_path:
            try:
                self.flow_table.export_to_csv(file_path)
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Results exported to:\n{file_path}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Export Failed",
                    f"Failed to export results:\n{str(e)}"
                )

    def clear_results(self):
        """Clear all results from table."""
        reply = QMessageBox.question(
            self,
            "Clear Results",
            "Are you sure you want to clear all results?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.flow_table.clear_flows()
            self.status_bar.showMessage("Results cleared", 3000)

    def refresh_view(self):
        """Refresh the view."""
        # Update statistics
        flow_count = self.flow_table.rowCount()
        alert_count = sum(1 for i in range(flow_count) 
                        if self.flow_table.item(i, 7) and 
                        self.flow_table.item(i, 7).text() in ['HIGH', 'CRITICAL'])
        
        self.stats_label.setText(f"Flows: {flow_count} | Alerts: {alert_count}")
        self.status_bar.showMessage("View refreshed", 2000)

    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About Hybrid IDS",
            "<h3>Hybrid Intrusion Detection System</h3>"
            "<p>Version 1.0.0</p>"
            "<p>A hybrid IDS combining machine learning (CNN + Random Forest) "
            "with signature-based detection (Suricata).</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>Real-time packet capture and analysis</li>"
            "<li>ML-based threat classification</li>"
            "<li>Signature-based detection integration</li>"
            "<li>Multi-class attack detection</li>"
            "</ul>"
            "<p>Built with Python, TensorFlow, scikit-learn, Scapy, and PyQt6.</p>"
        )

    def closeEvent(self, event):
        """Handle window close event."""
        if self.capture_active:
            reply = QMessageBox.question(
                self,
                "Capture Active",
                "Capture is still running. Stop and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_capture()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


    def init_ui(self):
        """Initialize user interface."""
        self.setWindowTitle("Hybrid Intrusion Detection System")
        self.setGeometry(100, 100, 1400, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header_layout = self._create_header()
        main_layout.addLayout(header_layout)
        
        # Control panel
        control_panel = self._create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Flow table
        self.flow_table = FlowTableView()
        main_layout.addWidget(self.flow_table)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(1000)  # Update every second
        
        logger.info("GUI initialized")
    
    def _create_header(self) -> QHBoxLayout:
        """Create header section."""
        layout = QHBoxLayout()
        
        title_label = QLabel("🛡️ Hybrid IDS")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        layout.addWidget(title_label)
        layout.addStretch()
        
        mode_label = QLabel(f"Mode: {self.mode.upper()}")
        layout.addWidget(mode_label)
        
        return layout
    
    def _create_control_panel(self) -> QGroupBox:
        """Create control panel."""
        group = QGroupBox("Controls")
        layout = QHBoxLayout()
        
        # Start/Stop button
        self.start_stop_btn = QPushButton("▶ Start Capture")
        self.start_stop_btn.setMinimumHeight(40)
        self.start_stop_btn.clicked.connect(self.toggle_capture)
        layout.addWidget(self.start_stop_btn)
        
        # Export button
        self.export_btn = QPushButton("💾 Export Data")
        self.export_btn.clicked.connect(self.export_data)
        layout.addWidget(self.export_btn)
        
        # Clear button
        self.clear_btn = QPushButton("🗑️ Clear Table")
        self.clear_btn.clicked.connect(self.clear_table)
        layout.addWidget(self.clear_btn)
        
        layout.addStretch()
        
        # Stats labels
        self.flows_label = QLabel("Flows: 0")
        self.threats_label = QLabel("Threats: 0")
        layout.addWidget(self.flows_label)
        layout.addWidget(self.threats_label)
        
        group.setLayout(layout)
        return group
    
    def toggle_capture(self):
        """Toggle capture on/off."""
        if not self.capture_active:
            self.start_capture()
        else:
            self.stop_capture()
    
    def start_capture(self):
        """Start packet capture."""
        if self.mode == 'live':
            self.start_live_capture()
        elif self.mode == 'offline':
            self.start_offline_analysis()
        elif self.mode == 'debug':
            self.start_debug_mode()
    
    def start_live_capture(self):
        """Start live packet capture."""
        try:
            # Check admin rights
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                QMessageBox.warning(
                    self,
                    "Administrator Rights Required",
                    "Live packet capture requires Administrator privileges.\n\n"
                    "Please close this application and restart by:\n"
                    "1. Right-click Command Prompt\n"
                    "2. Select 'Run as Administrator'\n"
                    "3. Navigate to the project folder\n"
                    "4. Run: run.bat"
                )
                return
            
            logger.info("Starting live capture...")
            self.capture_active = True
            self.start_stop_btn.setText("⏸ Stop Capture")
            self.status_bar.showMessage("Capturing live traffic... (generate network activity)")
            
            # Create wrapper callback that emits signals
            def signal_callback(result):
                """Thread-safe callback that emits Qt signal."""
                self.signals.flow_detected.emit(result)
            
            # Start capture in thread
            self.capture_thread = threading.Thread(
                target=self.controller.start_live_capture,
                args=(self.interface, signal_callback),
                daemon=True
            )
            self.capture_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start live capture: {e}")
            QMessageBox.critical(self, "Capture Error", str(e))
            self.capture_active = False


    
    def start_offline_analysis(self):
        """Start offline PCAP analysis."""
        try:
            # If no PCAP path provided, ask user
            if not self.pcap_path:
                file_path, _ = QFileDialog.getOpenFileName(
                    self,
                    "Select PCAP File",
                    str(Path.home()),
                    "PCAP Files (*.pcap *.pcapng);;All Files (*.*)"
                )
                
                if not file_path:
                    return
                
                self.pcap_path = Path(file_path)
            
            logger.info(f"Starting offline analysis: {self.pcap_path}")
            self.status_bar.showMessage(f"Analyzing {self.pcap_path.name}...")
            
            # Disable start button during analysis
            self.start_stop_btn.setEnabled(False)
            
            # Create wrapper callback that emits signals
            def signal_callback(result):
                """Thread-safe callback that emits Qt signal."""
                self.signals.flow_detected.emit(result)
            
            def analysis_thread():
                """Worker thread for offline analysis."""
                try:
                    # Analyze PCAP
                    flows = self.controller.analyze_pcap(
                        str(self.pcap_path),
                        callback=signal_callback
                    )
                    
                    # Signal completion
                    self.signals.analysis_complete.emit(len(flows))
                    
                except Exception as e:
                    logger.error(f"Offline analysis failed: {e}", exc_info=True)
                    self.signals.error.emit(f"Analysis failed: {str(e)}")
            
            # Start analysis in background thread
            self.capture_thread = threading.Thread(
                target=analysis_thread,
                daemon=True
            )
            self.capture_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start offline analysis: {e}")
            QMessageBox.critical(self, "Analysis Error", str(e))
            self.start_stop_btn.setEnabled(True)

    
    def start_debug_mode(self):
        """Start debug mode with synthetic flows."""
        try:
            logger.info("Starting debug mode with synthetic flows...")
            self.status_bar.showMessage("Generating synthetic flows for testing...")
            
            # Disable button during generation
            self.start_stop_btn.setEnabled(False)
            
            # Create wrapper callback that emits signals
            def signal_callback(result):
                """Thread-safe callback that emits Qt signal."""
                self.signals.flow_detected.emit(result)
            
            def debug_thread():
                """Worker thread for debug mode."""
                try:
                    from demo_data.generate_demo_flows import generate_synthetic_flow
                    import time
                    
                    # Generate and analyze synthetic flows
                    flow_count = 20  # Generate 20 test flows
                    
                    for i in range(flow_count):
                        # Generate synthetic flow
                        flow = generate_synthetic_flow()
                        
                        # Analyze it
                        result = self.controller._analyze_flow(flow)
                        
                        # Add flow info for display
                        result['flow_info'] = {
                            'src_ip': flow.get('src_ip', 'unknown'),
                            'dst_ip': flow.get('dst_ip', 'unknown'),
                            'src_port': flow.get('src_port', 0),
                            'dst_port': flow.get('dst_port', 0),
                            'protocol': flow.get('protocol', 6)
                        }
                        result['timestamp'] = datetime.now().isoformat()
                        
                        # Emit signal for GUI update
                        signal_callback(result)
                        
                        # Update status
                        self.signals.status_update.emit(
                            f"Generated flow {i+1}/{flow_count}"
                        )
                        
                        # Small delay to see flows appearing
                        time.sleep(0.1)
                    
                    # Signal completion
                    self.signals.analysis_complete.emit(flow_count)
                    
                except Exception as e:
                    logger.error(f"Debug mode failed: {e}", exc_info=True)
                    self.signals.error.emit(f"Debug mode failed: {str(e)}")
            
            # Start debug generation in background thread
            self.capture_thread = threading.Thread(
                target=debug_thread,
                daemon=True
            )
            self.capture_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start debug mode: {e}")
            QMessageBox.critical(self, "Debug Error", str(e))
            self.start_stop_btn.setEnabled(True)

    
    def stop_capture(self):
        """Stop capture."""
        logger.info("Stopping capture...")
        self.capture_active = False
        self.start_stop_btn.setText("▶ Start Capture")
        self.status_bar.showMessage("Capture stopped")
        
        self.controller.stop_capture()
    
    @pyqtSlot(dict)
    def on_flow_detected(self, result):
        """Handle flow detection"""
        try:
            # Unpack result dictionary
            flow = result.get('flow')
            prediction = result.get('prediction')
            suricata_result = result.get('suricata')
            
            # Add to table
            self.flow_table.add_flow(flow, prediction, suricata_result)
            
            # Update statistics (optional - comment out if method doesn't exist)
            # self.update_statistics()
            
        except Exception as e:
            logger.error(f"Failed to process flow: {e}")
            import traceback
            traceback.print_exc()


    @pyqtSlot(int)
    def on_analysis_complete(self, total_flows: int):
        """
        Called when offline analysis or debug mode completes.
        
        Args:
            total_flows: Total number of flows analyzed
        """
        self.status_bar.showMessage(
            f"Analysis complete - {total_flows} flows analyzed",
            5000
        )
        self.start_stop_btn.setEnabled(True)
        
        QMessageBox.information(
            self,
            "Analysis Complete",
            f"Successfully analyzed {total_flows} flows.\n\n"
            f"Results are displayed in the table below."
        )

    @pyqtSlot(str)
    def on_error(self, error_message: str):
        """
        Called when an error occurs in worker thread.
        
        Args:
            error_message: Error description
        """
        self.status_bar.showMessage(f"Error: {error_message}", 5000)
        self.start_stop_btn.setEnabled(True)
        
        QMessageBox.critical(
            self,
            "Error",
            f"An error occurred:\n\n{error_message}"
        )

    @pyqtSlot(str)
    def on_status_update(self, message: str):
        """
        Called to update status bar from worker thread.
        
        Args:
            message: Status message
        """
        self.status_bar.showMessage(message)
    
    def show_threat_alert(self, result: dict):
        """
        Show alert for detected threat.
        
        Args:
            result: Threat detection result
        """
        from inference.label_mapping import get_label_name
        
        flow_info = result.get('flow_info', {})
        classification_id = result.get('final_label', '0')
        classification_name = get_label_name(classification_id)
        confidence = result.get('final_confidence', 0.0)
        alert_level = result.get('alert_level', 'info')
        
        # Only show popup for critical threats to avoid spam
        if alert_level == 'critical' and confidence > 0.9:
            QMessageBox.warning(
                self,
                f"⚠ {alert_level.upper()} Alert",
                f"Threat detected: {classification_name}\n\n"
                f"Source: {flow_info.get('src_ip', 'unknown')}\n"
                f"Destination: {flow_info.get('dst_ip', 'unknown')}\n"
                f"Confidence: {confidence:.1%}\n\n"
                f"Check the flow table for details."
            )
    
    def update_display(self):
        """Update display with latest stats."""
        stats = self.flow_table.get_stats()
        self.flows_label.setText(f"Flows: {stats['total_flows']}")
        self.threats_label.setText(f"Threats: {stats['threat_count']}")
    
    def export_data(self):
        """Export data to file."""
        try:
            file_path, file_type = QFileDialog.getSaveFileName(
                self, "Export Data", "",
                "CSV Files (*.csv);;JSON Files (*.json);;All Files (*.*)"
            )
            
            if not file_path:
                return
            
            if file_path.endswith('.csv') or 'CSV' in file_type:
                self.flow_table.export_to_csv(file_path)
            else:
                self.flow_table.export_to_json(file_path)
            
            QMessageBox.information(self, "Export Success", 
                                  f"Data exported to {file_path}")
            logger.info(f"Data exported to {file_path}")
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            QMessageBox.critical(self, "Export Error", str(e))
    
    def clear_table(self):
        """Clear flow table."""
        reply = QMessageBox.question(
            self, "Clear Table",
            "Are you sure you want to clear all data?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.flow_table.clear()
            logger.info("Table cleared")
    
    def closeEvent(self, event):
        """Handle window close event."""
        if self.capture_active:
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "Capture is active. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            
            self.stop_capture()
        
        logger.info("Application closing")
        event.accept()

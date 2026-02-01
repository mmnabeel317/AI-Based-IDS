import logging
import threading
import time
from pathlib import Path
from typing import Optional, Callable, List, Dict
from datetime import datetime

from capture.packet_sniffer import PacketSniffer
from capture.pcap_offline_loader import PCAPLoader
from capture.flow_builder import FlowBuilder
from inference.predictor import HybridPredictor
from traditional_ids.suricata_parser import SuricataParser
from fusion.decision_engine import DecisionEngine
from utils.config import (
    FLOW_TIMEOUT,
    MAX_PACKETS_PER_FLOW,
    WSL_EVE_JSON,
    USE_WSL_SURICATA
)

logger = logging.getLogger(__name__)

class CaptureController:
    """
    Coordinates packet capture, flow building, and analysis.
    """
    
    def __init__(self, predictor: HybridPredictor, suricata_enabled: bool = True):
        """
        Initialize capture controller.
        
        Args:
            predictor: HybridPredictor instance for ML analysis
            suricata_enabled: Whether to use Suricata integration
        """
        self.predictor = predictor
        self.suricata_enabled = suricata_enabled
        
        # Initialize components
        self.flow_builder = FlowBuilder(
            timeout=FLOW_TIMEOUT,
            max_packets=MAX_PACKETS_PER_FLOW
        )
        
        # Initialize Suricata parser if enabled
        self.suricata_parser = None
        if suricata_enabled:
            try:
                eve_json_path = WSL_EVE_JSON if USE_WSL_SURICATA else None
                self.suricata_parser = SuricataParser(eve_json_path=eve_json_path)
                logger.info("Suricata parser initialized")
            except Exception as e:
                logger.warning(f"Suricata parser initialization failed: {e}")
        
        # Decision engine
        self.decision_engine = DecisionEngine()
        
        # Capture state
        self.capture_active = False
        self.stop_flag = threading.Event()
        
        logger.info("Capture controller initialized")
    
    def start_live_capture(self, interface: Optional[str] = None, 
                          callback: Optional[Callable] = None):
        """
        Start live packet capture and analysis.
        
        Args:
            interface: Network interface (None = auto-detect)
            callback: Callback function for flow results
        """
        try:
            logger.info(f"Starting live capture on {interface or 'default'}")
            
            self.capture_active = True
            self.stop_flag.clear()
            
            # Initialize packet sniffer
            sniffer = PacketSniffer(interface=interface)
            
            while self.capture_active and not self.stop_flag.is_set():
                try:
                    # Capture batch of packets
                    packets = sniffer.capture(count=50, timeout=5)
                    
                    if not packets:
                        continue
                    
                    # Build flows from packets
                    for packet in packets:
                        self.flow_builder.add_packet(packet)
                    
                    # Get completed flows
                    completed_flows = self.flow_builder.get_completed_flows()
                    
                    # Analyze each flow
                    for flow in completed_flows:
                        result = self._analyze_flow(flow)
                        
                        # Add flow metadata
                        result['flow_info'] = {
                            'src_ip': flow.get('src_ip', 'unknown'),
                            'dst_ip': flow.get('dst_ip', 'unknown'),
                            'src_port': flow.get('src_port', 0),
                            'dst_port': flow.get('dst_port', 0),
                            'protocol': flow.get('protocol', 6)
                        }
                        result['timestamp'] = datetime.now().isoformat()
                        
                        # Call callback if provided
                        if callback:
                            callback(result)
                    
                except KeyboardInterrupt:
                    logger.info("Capture interrupted by user")
                    break
                except Exception as e:
                    logger.error(f"Capture error: {e}", exc_info=True)
                    time.sleep(1)  # Brief pause before retry
            
            # Finalize remaining flows
            remaining_flows = self.flow_builder.finalize()
            for flow in remaining_flows:
                result = self._analyze_flow(flow)
                result['flow_info'] = {
                    'src_ip': flow.get('src_ip', 'unknown'),
                    'dst_ip': flow.get('dst_ip', 'unknown'),
                    'src_port': flow.get('src_port', 0),
                    'dst_port': flow.get('dst_port', 0),
                    'protocol': flow.get('protocol', 6)
                }
                result['timestamp'] = datetime.now().isoformat()
                
                if callback:
                    callback(result)
            
            logger.info("Live capture stopped")
            
        except Exception as e:
            logger.error(f"Live capture failed: {e}", exc_info=True)
            raise
    
    def stop_capture(self):
        """Stop ongoing capture."""
        logger.info("Stopping capture...")
        self.capture_active = False
        self.stop_flag.set()
    
    def analyze_pcap(self, pcap_path: str, 
                     callback: Optional[Callable] = None) -> List[Dict]:
        """
        Analyze PCAP file offline.
        
        Args:
            pcap_path: Path to PCAP file
            callback: Optional callback for each flow result
            
        Returns:
            List of analysis results
        """
        try:
            logger.info(f"Analyzing PCAP: {pcap_path}")
            
            # Load PCAP
            loader = PCAPLoader(pcap_path)
            packets = loader.load()
            
            # Build flows
            flow_builder = FlowBuilder(
                timeout=FLOW_TIMEOUT,
                max_packets=MAX_PACKETS_PER_FLOW
            )
            
            for packet in packets:
                flow_builder.add_packet(packet)
            
            # Get all flows (including incomplete)
            flows = flow_builder.finalize()
            logger.info(f"Built {len(flows)} flows")
            
            # Analyze each flow
            results = []
            for i, flow in enumerate(flows):
                try:
                    result = self._analyze_flow(flow)
                    
                    # Add flow metadata
                    result['flow_info'] = {
                        'src_ip': flow.get('src_ip', 'unknown'),
                        'dst_ip': flow.get('dst_ip', 'unknown'),
                        'src_port': flow.get('src_port', 0),
                        'dst_port': flow.get('dst_port', 0),
                        'protocol': flow.get('protocol', 6)
                    }
                    result['timestamp'] = datetime.now().isoformat()
                    
                    results.append(result)
                    
                    # Call callback if provided
                    if callback:
                        callback(result)
                    
                    # Log progress every 100 flows
                    if (i + 1) % 100 == 0:
                        logger.info(f"Analyzed {i + 1}/{len(flows)} flows")
                        
                except Exception as e:
                    logger.error(f"Flow analysis failed: {e}", exc_info=True)
                    continue
            
            logger.info("PCAP analysis complete")
            return results
            
        except Exception as e:
            logger.error(f"PCAP analysis failed: {e}", exc_info=True)
            raise
    
    def _analyze_flow(self, flow: dict) -> dict:
        """
        Analyze a single flow.
        
        Args:
            flow: Flow dictionary
            
        Returns:
            Analysis result
        """
        try:
            # ML prediction
            prediction = self.predictor.predict(flow)
            
            # Get Suricata alert if available
            suricata_alert = None
            if self.suricata_parser:
                suricata_alert = self.suricata_parser.get_alert_for_flow(flow)
            
            # Fusion decision
            result = self.decision_engine.make_decision(prediction, suricata_alert)
            
            return result
            
        except Exception as e:
            logger.error(f"Flow analysis failed: {e}", exc_info=True)
            # Return error result
            return {
                'final_label': '0',
                'final_confidence': 0.0,
                'alert_level': 'error',
                'flow_info': {
                    'src_ip': flow.get('src_ip', 'unknown'),
                    'dst_ip': flow.get('dst_ip', 'unknown'),
                    'src_port': flow.get('src_port', 0),
                    'dst_port': flow.get('dst_port', 0),
                    'protocol': flow.get('protocol', 6)
                },
                'models': {
                    'cnn': {'predicted_class': '0', 'confidence': 0.0},
                    'rf': {'predicted_class': '0', 'confidence': 0.0}
                },
                'error': str(e)
            }
    
    def get_stats(self) -> Dict:
        """
        Get capture statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'capture_active': self.capture_active,
            'flows_built': len(self.flow_builder.flows),
            'suricata_enabled': self.suricata_enabled
        }
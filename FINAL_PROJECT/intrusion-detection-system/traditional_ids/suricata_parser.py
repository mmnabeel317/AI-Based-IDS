"""
Suricata Parser Module
Parses eve.json alerts and correlates with flows.
"""

import logging
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class SuricataParser:
    """Parses Suricata eve.json output."""
    
    def __init__(self, eve_json_path: Optional[str] = None):
        """
        Initialize Suricata parser.
        
        Args:
            eve_json_path: Path to eve.json file
        """
        self.eve_json_path = Path(eve_json_path) if eve_json_path else None
        self.alerts_cache: List[Dict] = []
        self.last_read_position = 0
        
        if self.eve_json_path and self.eve_json_path.exists():
            logger.info(f"Suricata parser initialized: {self.eve_json_path}")
        else:
            logger.warning("Eve.json file not found - will parse when available")
    
    def parse_alerts(self, limit: int = None) -> List[Dict]:
        """
        Parse alerts from eve.json.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of alert dictionaries
        """
        if not self.eve_json_path or not self.eve_json_path.exists():
            logger.debug("Eve.json not available")
            return []
        
        alerts = []
        
        try:
            with open(self.eve_json_path, 'r', encoding='utf-8') as f:
                # Seek to last read position for incremental reading
                f.seek(self.last_read_position)
                
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        
                        # Only process alert events
                        if event.get('event_type') == 'alert':
                            alert = self._parse_alert_event(event)
                            alerts.append(alert)
                            
                            if limit and len(alerts) >= limit:
                                break
                                
                    except json.JSONDecodeError as e:
                        logger.debug(f"Skipping invalid JSON line: {e}")
                        continue
                
                # Update read position
                self.last_read_position = f.tell()
            
            # Cache alerts
            self.alerts_cache.extend(alerts)
            
            logger.info(f"Parsed {len(alerts)} new alerts")
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to parse eve.json: {e}")
            return []
    
    def _parse_alert_event(self, event: Dict) -> Dict:
        """Parse individual alert event."""
        alert_data = event.get('alert', {})
        
        alert = {
            'timestamp': event.get('timestamp'),
            'signature': alert_data.get('signature', 'Unknown'),
            'signature_id': alert_data.get('signature_id', 0),
            'category': alert_data.get('category', 'Unknown'),
            'severity': alert_data.get('severity', 3),
            'src_ip': event.get('src_ip'),
            'dst_ip': event.get('dest_ip'),
            'src_port': event.get('src_port', 0),
            'dst_port': event.get('dest_port', 0),
            'protocol': event.get('proto', 'unknown'),
            'flow_id': event.get('flow_id'),
            'raw_event': event
        }
        
        return alert
    
    def get_alert_for_flow(self, flow: Dict) -> Optional[Dict]:
        """
        Get matching alert for a flow (5-tuple correlation).
        
        Args:
            flow: Flow dictionary
            
        Returns:
            Matching alert or None
        """
        # Parse latest alerts
        self.parse_alerts()
        
        # Extract flow 5-tuple
        flow_src_ip = flow.get('src_ip')
        flow_dst_ip = flow.get('dst_ip')
        flow_src_port = flow.get('src_port', 0)
        flow_dst_port = flow.get('dst_port', 0)
        flow_proto = flow.get('protocol', 6)
        
        # Search for matching alert
        for alert in reversed(self.alerts_cache):  # Search most recent first
            # Check if 5-tuple matches (bidirectional)
            if self._match_flow(alert, flow_src_ip, flow_dst_ip, flow_src_port, flow_dst_port, flow_proto):
                logger.info(f"Found matching Suricata alert: {alert['signature']}")
                return alert
        
        return None
    
    def _match_flow(self, alert: Dict, src_ip: str, dst_ip: str, 
                    src_port: int, dst_port: int, protocol: int) -> bool:
        """Check if alert matches flow 5-tuple (bidirectional)."""
        alert_src = alert.get('src_ip')
        alert_dst = alert.get('dst_ip')
        alert_sport = alert.get('src_port', 0)
        alert_dport = alert.get('dst_port', 0)
        
        # Convert protocol
        protocol_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        proto_str = protocol_map.get(protocol, 'unknown').upper()
        alert_proto = alert.get('protocol', '').upper()
        
        # Check forward direction
        if (alert_src == src_ip and alert_dst == dst_ip and
            alert_sport == src_port and alert_dport == dst_port and
            alert_proto == proto_str):
            return True
        
        # Check reverse direction
        if (alert_src == dst_ip and alert_dst == src_ip and
            alert_sport == dst_port and alert_dport == src_port and
            alert_proto == proto_str):
            return True
        
        return False
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        """
        Get recent alerts from cache.
        
        Args:
            limit: Maximum number of alerts
            
        Returns:
            List of recent alerts
        """
        return self.alerts_cache[-limit:]
    
    def clear_cache(self):
        """Clear alerts cache."""
        self.alerts_cache.clear()
        logger.info("Alerts cache cleared")
    
    def get_stats(self) -> Dict:
        """Get parser statistics."""
        return {
            'cached_alerts': len(self.alerts_cache),
            'eve_json_path': str(self.eve_json_path) if self.eve_json_path else None,
            'last_read_position': self.last_read_position
        }

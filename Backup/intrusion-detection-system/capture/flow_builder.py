"""
Flow Builder Module
Aggregates packets into network flows (5-tuple sessions).
"""

import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class FlowBuilder:
    """
    Builds network flows from individual packets.
    Groups packets by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
    """
    
    def __init__(self, timeout: int = 120, max_packets: int = 10000):
        """
        Initialize flow builder.
        
        Args:
            timeout: Flow timeout in seconds (flows inactive for this long are considered complete)
            max_packets: Maximum packets per flow before forcing completion
        """
        self.timeout = timeout
        self.max_packets = max_packets
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'last_time': None,
            'packet_count': 0
        })
        
        logger.info(f"Flow builder initialized: timeout={timeout}s, max_packets={max_packets}")
    
    def add_packet(self, packet: Dict) -> Optional[Dict]:
        """
        Add packet to flow builder.
        
        Args:
            packet: Packet dictionary with at least src_ip, dst_ip, protocol
            
        Returns:
            Completed flow if packet triggers flow completion, None otherwise
        """
        flow_key = self._extract_flow_key(packet)
        
        if flow_key is None:
            return None
        
        flow = self.flows[flow_key]
        
        # Initialize flow if first packet
        if flow['start_time'] is None:
            flow['start_time'] = packet.get('timestamp', datetime.now())
        
        # Add packet to flow
        flow['packets'].append(packet)
        flow['last_time'] = packet.get('timestamp', datetime.now())
        flow['packet_count'] += 1
        
        # Check if flow is complete (max packets reached)
        if flow['packet_count'] >= self.max_packets:
            completed = self._finalize_flow(flow_key, flow)
            del self.flows[flow_key]
            return completed
        
        return None
    
    def get_completed_flows(self, force_timeout: bool = True) -> List[Dict]:
        """
        Get flows that have timed out or are complete.
        
        Args:
            force_timeout: Whether to check for timed-out flows
            
        Returns:
            List of completed flows
        """
        if not force_timeout:
            return []
        
        completed = []
        now = datetime.now()
        expired_keys = []
        
        for flow_key, flow in self.flows.items():
            if flow['last_time'] is None:
                continue
            
            # Check timeout
            last_time = flow['last_time']
            if isinstance(last_time, str):
                try:
                    last_time = datetime.fromisoformat(last_time)
                except:
                    last_time = datetime.now()
            
            elapsed = (now - last_time).total_seconds()
            
            if elapsed > self.timeout:
                completed.append(self._finalize_flow(flow_key, flow))
                expired_keys.append(flow_key)
        
        # Remove expired flows
        for key in expired_keys:
            del self.flows[key]
        
        return completed
    
    def finalize(self) -> List[Dict]:
        """
        Finalize all remaining flows.
        Call this when capture is complete.
        
        Returns:
            List of all remaining flows
        """
        completed = []
        
        for flow_key, flow in self.flows.items():
            completed.append(self._finalize_flow(flow_key, flow))
        
        logger.info(f"Finalized {len(completed)} active flows")
        self.flows.clear()
        
        return completed
    
    def _extract_flow_key(self, packet: Dict) -> Optional[Tuple]:
        """
        Extract 5-tuple flow key from packet.
        
        Args:
            packet: Packet dictionary
            
        Returns:
            Tuple of (src_ip, dst_ip, src_port, dst_port, protocol) or None
        """
        try:
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            protocol = packet.get('protocol', 6)
            
            # Must have at least IPs
            if src_ip is None or dst_ip is None:
                return None
            
            # For non-TCP/UDP, ports might be 0
            if protocol not in [6, 17]:  # Not TCP or UDP
                src_port = 0
                dst_port = 0
            
            # Normalize flow direction (smaller IP first for bidirectional)
            if src_ip < dst_ip:
                return (src_ip, dst_ip, src_port, dst_port, protocol)
            elif src_ip > dst_ip:
                return (dst_ip, src_ip, dst_port, src_port, protocol)
            else:
                # Same IP, use port ordering
                if src_port <= dst_port:
                    return (src_ip, dst_ip, src_port, dst_port, protocol)
                else:
                    return (dst_ip, src_ip, dst_port, src_port, protocol)
                    
        except Exception as e:
            logger.debug(f"Failed to extract flow key: {e}")
            return None
    
    def _finalize_flow(self, flow_key: Tuple, flow_data: Dict) -> Dict:
        """
        Convert flow data to final flow dictionary.
        
        Args:
            flow_key: 5-tuple flow key
            flow_data: Flow data with packets and metadata
            
        Returns:
            Finalized flow dictionary
        """
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        
        packets = flow_data['packets']
        packet_count = len(packets)
        
        # Calculate duration
        start_time = flow_data['start_time']
        last_time = flow_data['last_time']
        
        if isinstance(start_time, str):
            try:
                start_time = datetime.fromisoformat(start_time)
            except:
                start_time = datetime.now()
        
        if isinstance(last_time, str):
            try:
                last_time = datetime.fromisoformat(last_time)
            except:
                last_time = datetime.now()
        
        duration = (last_time - start_time).total_seconds()
        
        # Calculate statistics
        total_bytes = sum(p.get('length', 0) for p in packets)
        avg_packet_size = total_bytes / packet_count if packet_count > 0 else 0
        
        # Count flags (TCP)
        syn_count = sum(1 for p in packets if p.get('flags', {}).get('S', False))
        ack_count = sum(1 for p in packets if p.get('flags', {}).get('A', False))
        fin_count = sum(1 for p in packets if p.get('flags', {}).get('F', False))
        rst_count = sum(1 for p in packets if p.get('flags', {}).get('R', False))
        
        # Build flow dictionary
        flow = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packets': packets,
            'packet_count': packet_count,
            'total_bytes': total_bytes,
            'duration': duration,
            'start_time': start_time.isoformat() if isinstance(start_time, datetime) else str(start_time),
            'end_time': last_time.isoformat() if isinstance(last_time, datetime) else str(last_time),
            'avg_packet_size': avg_packet_size,
            'syn_count': syn_count,
            'ack_count': ack_count,
            'fin_count': fin_count,
            'rst_count': rst_count
        }
        
        return flow
    
    def get_stats(self) -> Dict:
        """
        Get flow builder statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'active_flows': len(self.flows),
            'timeout': self.timeout,
            'max_packets': self.max_packets,
            'total_packets': sum(f['packet_count'] for f in self.flows.values())
        }

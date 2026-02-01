"""
Flow Builder - Creates network flows from packets
"""

import time
from collections import defaultdict
from utils.logger import get_logger

logger = get_logger(__name__)


class FlowBuilder:
    """Builds network flows from captured packets"""
    
    def __init__(self, timeout=120, activity_timeout=5, max_packets=None, flow_timeout=None):
        """
        Args:
            timeout: Max seconds for a flow to stay active
            activity_timeout: Max seconds of inactivity before flow ends
            max_packets: Maximum packets per flow
            flow_timeout: Alternative name for timeout
        """
        self.flow_timeout = flow_timeout if flow_timeout is not None else timeout
        self.activity_timeout = activity_timeout
        self.max_packets = max_packets if max_packets is not None else 10000
        self.flows = {}
        self.completed_flows = []
        
        logger.info(f"FlowBuilder initialized: timeout={self.flow_timeout}s, "
                   f"activity_timeout={self.activity_timeout}s, max_packets={self.max_packets}")
        
    def add_packet(self, packet_info):
        """Add packet to appropriate flow"""
        try:
            # Validate packet_info
            if not isinstance(packet_info, dict):
                logger.error(f"packet_info is not a dict: {type(packet_info)}")
                return None
            
            # Create flow key
            flow_key = self._get_flow_key(packet_info)
            if not flow_key:
                return None
            
            current_time = packet_info.get('timestamp', time.time())
            
            # Get or create flow
            if flow_key not in self.flows:
                self.flows[flow_key] = self._create_new_flow(packet_info, current_time)
            
            flow = self.flows[flow_key]
            
            # Add packet to flow
            flow['packets'].append(packet_info)
            flow['flow_last_seen'] = current_time
            flow['packet_count'] += 1
            
            # Determine direction
            is_forward = self._is_forward_packet(packet_info, flow)
            packet_info['direction'] = 'forward' if is_forward else 'backward'
            
            if is_forward:
                flow['forward_packets'].append(packet_info)
            else:
                flow['backward_packets'].append(packet_info)
            
            # Check if flow should be completed
            flow_duration = current_time - flow['flow_start_time']
            should_complete = False
            
            if flow_duration > self.flow_timeout:
                should_complete = True
            
            if flow['packet_count'] >= self.max_packets:
                should_complete = True
            
            if should_complete:
                return self._complete_flow(flow_key)
            
            return None
            
        except Exception as e:
            logger.error(f"Error adding packet to flow: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _get_flow_key(self, packet_info):
        """Generate unique flow key (bidirectional)"""
        try:
            # Extract with proper error handling
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            src_port = packet_info.get('src_port', 0)
            dst_port = packet_info.get('dst_port', 0)
            protocol = packet_info.get('protocol')
            
            # Validate required fields
            if not src_ip or not dst_ip or not protocol:
                logger.debug(f"Missing required fields: src_ip={src_ip}, dst_ip={dst_ip}, protocol={protocol}")
                return None
            
            # Create bidirectional key (sorted for consistency)
            if (src_ip, src_port) < (dst_ip, dst_port):
                return (src_ip, src_port, dst_ip, dst_port, protocol)
            else:
                return (dst_ip, dst_port, src_ip, src_port, protocol)
                
        except Exception as e:
            logger.error(f"Error creating flow key: {e}")
            logger.error(f"Packet info: {packet_info}")
            import traceback
            traceback.print_exc()
            return None
    
    def _create_new_flow(self, packet_info, current_time):
        """Create new flow structure"""
        return {
            'flow_id': f"flow_{int(current_time * 1000)}_{id(packet_info)}",
            'src_ip': packet_info.get('src_ip', ''),
            'dst_ip': packet_info.get('dst_ip', ''),
            'src_port': packet_info.get('src_port', 0),
            'dst_port': packet_info.get('dst_port', 0),
            'protocol': packet_info.get('protocol', ''),
            'flow_start_time': current_time,
            'flow_last_seen': current_time,
            'packets': [],
            'forward_packets': [],
            'backward_packets': [],
            'packet_count': 0,
            'first_src_ip': packet_info.get('src_ip', ''),
            'first_src_port': packet_info.get('src_port', 0)
        }
    
    def _is_forward_packet(self, packet_info, flow):
        """Determine if packet is forward direction"""
        return (packet_info.get('src_ip') == flow['first_src_ip'] and 
                packet_info.get('src_port') == flow['first_src_port'])
    
    def _complete_flow(self, flow_key):
        """Complete and return a flow"""
        if flow_key not in self.flows:
            return None
        
        flow = self.flows.pop(flow_key)
        self.completed_flows.append(flow)
        
        logger.debug(f"Flow completed: {flow['flow_id']} | "
                    f"Duration: {flow['flow_last_seen'] - flow['flow_start_time']:.2f}s | "
                    f"Packets: {flow['packet_count']} | "
                    f"Fwd: {len(flow['forward_packets'])} | "
                    f"Bwd: {len(flow['backward_packets'])}")
        
        return flow
    
    def get_active_flows(self):
        """Get all currently active flows"""
        return list(self.flows.values())
    
    def flush_inactive_flows(self):
        """Complete flows that have been inactive"""
        current_time = time.time()
        inactive_keys = []
        
        for key, flow in self.flows.items():
            inactivity = current_time - flow['flow_last_seen']
            if inactivity > self.activity_timeout:
                inactive_keys.append(key)
        
        completed = []
        for key in inactive_keys:
            flow = self._complete_flow(key)
            if flow:
                completed.append(flow)
        
        if completed:
            logger.info(f"Flushed {len(completed)} inactive flows")
        
        return completed
    
    def flush_all_flows(self):
        """Complete all active flows"""
        completed = []
        keys = list(self.flows.keys())
        
        for key in keys:
            flow = self._complete_flow(key)
            if flow:
                completed.append(flow)
        
        if completed:
            logger.info(f"Flushed all {len(completed)} active flows")
        
        return completed
    
    def finalize(self):
        """
        Finalize and return all flows.
        
        Returns:
            list: All completed flows
        """
        logger.info(f"Finalizing flows: {len(self.flows)} active, {len(self.completed_flows)} completed")
        
        # Complete all remaining active flows
        self.flush_all_flows()
        
        # Return all completed flows
        all_flows = self.completed_flows.copy()
        
        logger.info(f"✓ Finalized {len(all_flows)} total flows")
        
        return all_flows
    
    def get_all_flows(self):
        """Get all flows (active + completed)"""
        return self.completed_flows + list(self.flows.values())
    
    def get_flow_count(self):
        """Get count of flows"""
        return {
            'active': len(self.flows),
            'completed': len(self.completed_flows),
            'total': len(self.flows) + len(self.completed_flows)
        }
    
    def reset(self):
        """Reset flow builder state"""
        self.flows.clear()
        self.completed_flows.clear()
        logger.info("FlowBuilder reset")

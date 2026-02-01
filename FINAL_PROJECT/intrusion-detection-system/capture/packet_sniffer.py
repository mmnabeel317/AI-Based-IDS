"""
Packet Sniffer Module
Live packet capture using Scapy with Windows/Npcap support.
"""

import logging
from typing import List, Dict, Optional
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Captures network packets using Scapy."""
    
    def __init__(self, interface: Optional[str] = None, filter_str: str = ""):
        """
        Initialize packet sniffer.
        
        Args:
            interface: Network interface name (auto-detect if None)
            filter_str: BPF filter string (e.g., "tcp port 80")
        """
        self.interface = interface
        self.filter_str = filter_str
        self.packets_captured = 0
        
        try:
            from scapy.all import conf, get_if_list
            
            # Auto-detect interface if not specified
            if self.interface is None:
                # Use Scapy's default interface (which we know works!)
                self.interface = conf.iface
                logger.info(f"Using Scapy default interface: {self.interface}")
            else:
                logger.info(f"Using specified interface: {self.interface}")
            
            logger.info(f"Packet sniffer initialized on {self.interface}")
            
        except ImportError as e:
            logger.error(f"Scapy not available: {e}")
            raise

    
    def capture(self, count: int = 100, timeout: int = 30) -> List[Dict]:
        """
        Capture packets from network.
        
        Args:
            count: Number of packets to capture
            timeout: Timeout in seconds
            
        Returns:
            List of packet dictionaries
        """
        try:
            from scapy.all import sniff
            
            logger.info(f"Starting capture: count={count}, timeout={timeout}s")
            
            packets = sniff(
                iface=self.interface,
                filter=self.filter_str,
                count=count,
                timeout=timeout,
                store=True
            )
            
            self.packets_captured = len(packets)
            logger.info(f"Captured {self.packets_captured} packets")
            
            # Convert to dictionaries
            packet_dicts = [self._packet_to_dict(pkt) for pkt in packets]
            
            return packet_dicts
            
        except PermissionError:
            logger.error("Permission denied - run as Administrator for live capture")
            raise
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            raise
    
    def capture_continuous(self, callback, stop_event):
        """
        Continuous capture mode with callback.
        
        Args:
            callback: Function to call for each packet
            stop_event: Threading event to signal stop
        """
        try:
            from scapy.all import sniff
            
            logger.info("Starting continuous capture...")
            
            def packet_handler(pkt):
                if stop_event.is_set():
                    return True  # Stop sniffing
                
                pkt_dict = self._packet_to_dict(pkt)
                callback(pkt_dict)
                self.packets_captured += 1
            
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: stop_event.is_set()
            )
            
            logger.info(f"Continuous capture stopped: {self.packets_captured} packets")
            
        except Exception as e:
            logger.error(f"Continuous capture failed: {e}")
            raise
    
    def _packet_to_dict(self, pkt) -> Dict:
        """
        Convert Scapy packet to dictionary.
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            Dictionary with packet fields
        """
        from scapy.all import IP, TCP, UDP, ICMP
        
        pkt_dict = {
            'timestamp': time.time(),
            'length': len(pkt)
        }
        
        # IP layer
        if IP in pkt:
            pkt_dict['src_ip'] = pkt[IP].src
            pkt_dict['dst_ip'] = pkt[IP].dst
            pkt_dict['protocol'] = pkt[IP].proto
            pkt_dict['ttl'] = pkt[IP].ttl
        
        # TCP layer
        if TCP in pkt:
            pkt_dict['src_port'] = pkt[TCP].sport
            pkt_dict['dst_port'] = pkt[TCP].dport
            pkt_dict['syn'] = bool(pkt[TCP].flags & 0x02)
            pkt_dict['ack'] = bool(pkt[TCP].flags & 0x10)
            pkt_dict['fin'] = bool(pkt[TCP].flags & 0x01)
            pkt_dict['rst'] = bool(pkt[TCP].flags & 0x04)
            pkt_dict['psh'] = bool(pkt[TCP].flags & 0x08)
            pkt_dict['urg'] = bool(pkt[TCP].flags & 0x20)
            pkt_dict['window'] = pkt[TCP].window
            pkt_dict['seq'] = pkt[TCP].seq
            pkt_dict['ack_num'] = pkt[TCP].ack
            
            # Payload
            if pkt[TCP].payload:
                pkt_dict['payload_length'] = len(pkt[TCP].payload)
            else:
                pkt_dict['payload_length'] = 0
        
        # UDP layer
        elif UDP in pkt:
            pkt_dict['src_port'] = pkt[UDP].sport
            pkt_dict['dst_port'] = pkt[UDP].dport
            pkt_dict['protocol'] = 17
            
            if pkt[UDP].payload:
                pkt_dict['payload_length'] = len(pkt[UDP].payload)
            else:
                pkt_dict['payload_length'] = 0
        
        # ICMP layer
        elif ICMP in pkt:
            pkt_dict['protocol'] = 1
            pkt_dict['icmp_type'] = pkt[ICMP].type
            pkt_dict['icmp_code'] = pkt[ICMP].code
        
        return pkt_dict
    
    @staticmethod
    def list_interfaces() -> List[str]:
        """
        List available network interfaces.
        
        Returns:
            List of interface names
        """
        try:
            from scapy.all import get_if_list, get_windows_if_list
            import platform
            
            if platform.system() == 'Windows':
                # Windows-specific interface listing
                ifaces = get_windows_if_list()
                return [iface['name'] for iface in ifaces]
            else:
                return get_if_list()
                
        except Exception as e:
            logger.error(f"Failed to list interfaces: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Get capture statistics."""
        return {
            'packets_captured': self.packets_captured,
            'interface': self.interface,
            'filter': self.filter_str
        }

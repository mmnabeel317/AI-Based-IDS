"""
PCAP Offline Loader Module
Loads and parses packets from PCAP files.
"""

import logging
from pathlib import Path
from typing import List, Dict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from datetime import datetime

logger = logging.getLogger(__name__)

class PCAPLoader:
    """
    Loads packets from PCAP files.
    """
    
    def __init__(self, pcap_path: str):
        """
        Initialize PCAP loader.
        
        Args:
            pcap_path: Path to PCAP file
        """
        self.pcap_path = Path(pcap_path)
        
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        logger.info(f"PCAP loader initialized: {pcap_path}")
    
    def load(self) -> List[Dict]:
        """
        Load packets from PCAP file.
        
        Returns:
            List of packet dictionaries
        """
        try:
            logger.info(f"Loading PCAP: {self.pcap_path}")
            
            # Read PCAP file using Scapy
            packets = rdpcap(str(self.pcap_path))
            
            logger.info(f"Loaded {len(packets)} packets from PCAP")
            
            # Convert Scapy packets to dictionaries
            packet_dicts = []
            for i, pkt in enumerate(packets):
                try:
                    pkt_dict = self._packet_to_dict(pkt, i)
                    if pkt_dict:
                        packet_dicts.append(pkt_dict)
                except Exception as e:
                    logger.debug(f"Failed to parse packet {i}: {e}")
                    continue
            
            logger.info(f"Converted {len(packet_dicts)} valid packets")
            
            return packet_dicts
            
        except Exception as e:
            logger.error(f"Failed to load PCAP: {e}", exc_info=True)
            raise
    
    def _packet_to_dict(self, pkt, index: int) -> Dict:
        """
        Convert Scapy packet to dictionary.
        
        Args:
            pkt: Scapy packet
            index: Packet index
            
        Returns:
            Packet dictionary or None if invalid
        """
        try:
            packet_dict = {
                'index': index,
                'timestamp': datetime.fromtimestamp(float(pkt.time)).isoformat(),
                'length': len(pkt)
            }
            
            # IP layer
            if IP in pkt:
                packet_dict['src_ip'] = pkt[IP].src
                packet_dict['dst_ip'] = pkt[IP].dst
                packet_dict['protocol'] = pkt[IP].proto
                packet_dict['ttl'] = pkt[IP].ttl
                packet_dict['ip_len'] = pkt[IP].len
            else:
                # No IP layer, skip this packet
                return None
            
            # TCP layer
            if TCP in pkt:
                packet_dict['src_port'] = pkt[TCP].sport
                packet_dict['dst_port'] = pkt[TCP].dport
                packet_dict['protocol'] = 6  # TCP
                
                # TCP flags
                flags = pkt[TCP].flags
                packet_dict['flags'] = {
                    'F': bool(flags & 0x01),  # FIN
                    'S': bool(flags & 0x02),  # SYN
                    'R': bool(flags & 0x04),  # RST
                    'P': bool(flags & 0x08),  # PSH
                    'A': bool(flags & 0x10),  # ACK
                    'U': bool(flags & 0x20),  # URG
                }
                
                packet_dict['seq'] = pkt[TCP].seq
                packet_dict['ack'] = pkt[TCP].ack
                packet_dict['window'] = pkt[TCP].window
            
            # UDP layer
            elif UDP in pkt:
                packet_dict['src_port'] = pkt[UDP].sport
                packet_dict['dst_port'] = pkt[UDP].dport
                packet_dict['protocol'] = 17  # UDP
                packet_dict['udp_len'] = pkt[UDP].len
            
            # ICMP layer
            elif ICMP in pkt:
                packet_dict['protocol'] = 1  # ICMP
                packet_dict['icmp_type'] = pkt[ICMP].type
                packet_dict['icmp_code'] = pkt[ICMP].code
                packet_dict['src_port'] = 0
                packet_dict['dst_port'] = 0
            
            else:
                # Other protocols - set default ports
                packet_dict['src_port'] = 0
                packet_dict['dst_port'] = 0
            
            # Payload
            if hasattr(pkt, 'load'):
                packet_dict['payload_len'] = len(pkt.load)
            else:
                packet_dict['payload_len'] = 0
            
            return packet_dict
            
        except Exception as e:
            logger.debug(f"Failed to convert packet to dict: {e}")
            return None
    
    def get_metadata(self) -> Dict:
        """
        Get PCAP file metadata without loading all packets.
        
        Returns:
            Dictionary with file metadata
        """
        try:
            packets = rdpcap(str(self.pcap_path))
            
            metadata = {
                'file_path': str(self.pcap_path),
                'file_size': self.pcap_path.stat().st_size,
                'packet_count': len(packets),
            }
            
            if packets:
                metadata['first_packet_time'] = datetime.fromtimestamp(
                    float(packets[0].time)
                ).isoformat()
                metadata['last_packet_time'] = datetime.fromtimestamp(
                    float(packets[-1].time)
                ).isoformat()
            
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to get metadata: {e}")
            return {
                'file_path': str(self.pcap_path),
                'error': str(e)
            }    
    def get_pcap_info(self) -> Dict:
        """
        Get information about PCAP file.
        
        Returns:
            Dictionary with file info
        """
        try:
            from scapy.all import rdpcap
            
            packets = rdpcap(str(self.pcap_path))
            
            return {
                'path': str(self.pcap_path),
                'size_bytes': self.pcap_path.stat().st_size,
                'packet_count': len(packets),
                'readable': True
            }
            
        except Exception as e:
            logger.error(f"Failed to read PCAP info: {e}")
            return {
                'path': str(self.pcap_path),
                'size_bytes': self.pcap_path.stat().st_size if self.pcap_path.exists() else 0,
                'packet_count': 0,
                'readable': False,
                'error': str(e)
            }

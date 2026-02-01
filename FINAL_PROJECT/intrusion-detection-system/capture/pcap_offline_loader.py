"""
PCAP Offline Loader - Loads packets from PCAP files
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from utils.logger import get_logger

logger = get_logger(__name__)


class PCAPLoader:
    """Loads and processes PCAP files"""
    
    def __init__(self, pcap_path):
        """
        Initialize PCAP loader.
        
        Args:
            pcap_path (str): Path to PCAP file
        """
        self.pcap_path = pcap_path
        self.packets = []
        logger.info(f"PCAP loader initialized: {pcap_path}")
    
    def load(self):
        """Load PCAP file using scapy"""
        try:
            logger.info(f"Loading PCAP: {self.pcap_path}")
            self.packets = rdpcap(self.pcap_path)
            logger.info(f"Loaded {len(self.packets)} packets from PCAP")
            return self.packets
        except Exception as e:
            logger.error(f"Failed to load PCAP: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def convert_to_dict_format(self):
        """
        Convert scapy packets to dictionary format for flow builder.
        
        Returns:
            list: List of packet dictionaries
        """
        converted = []
        
        for i, pkt in enumerate(self.packets):
            try:
                packet_dict = self._packet_to_dict(pkt, i)
                if packet_dict:
                    converted.append(packet_dict)
            except Exception as e:
                logger.debug(f"Skipped packet {i}: {e}")
                continue
        
        logger.info(f"Converted {len(converted)} valid packets")
        return converted
    
    def _packet_to_dict(self, pkt, index):
        """
        Convert a scapy packet to dictionary format.
        
        Args:
            pkt: Scapy packet
            index (int): Packet index
        
        Returns:
            dict: Packet information dictionary
        """
        try:
            # Must have IP layer
            if not pkt.haslayer(IP):
                return None
            
            ip = pkt[IP]
            
            # Base packet dictionary
            packet_dict = {
                'index': index,
                'timestamp': float(pkt.time),
                'src_ip': str(ip.src),
                'dst_ip': str(ip.dst),
                'length': len(pkt),
                'size': len(pkt)
            }
            
            # Protocol-specific fields
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                packet_dict['protocol'] = 'TCP'
                packet_dict['src_port'] = int(tcp.sport)
                packet_dict['dst_port'] = int(tcp.dport)
                packet_dict['window'] = int(tcp.window)
                packet_dict['header_length'] = int(tcp.dataofs * 4)
                packet_dict['flags'] = self._get_tcp_flags(tcp)
                
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                packet_dict['protocol'] = 'UDP'
                packet_dict['src_port'] = int(udp.sport)
                packet_dict['dst_port'] = int(udp.dport)
                packet_dict['window'] = 0
                packet_dict['header_length'] = 8
                packet_dict['flags'] = {}
                
            elif pkt.haslayer(ICMP):
                packet_dict['protocol'] = 'ICMP'
                packet_dict['src_port'] = 0
                packet_dict['dst_port'] = 0
                packet_dict['window'] = 0
                packet_dict['header_length'] = 8
                packet_dict['flags'] = {}
                
            else:
                packet_dict['protocol'] = 'OTHER'
                packet_dict['src_port'] = 0
                packet_dict['dst_port'] = 0
                packet_dict['window'] = 0
                packet_dict['header_length'] = 20
                packet_dict['flags'] = {}
            
            return packet_dict
            
        except Exception as e:
            logger.debug(f"Error converting packet {index}: {e}")
            return None
    
    def _get_tcp_flags(self, tcp):
        """
        Extract TCP flags as dictionary.
        
        Args:
            tcp: TCP layer
        
        Returns:
            dict: TCP flags
        """
        try:
            flags_value = int(tcp.flags)
            return {
                'FIN': bool(flags_value & 0x01),
                'SYN': bool(flags_value & 0x02),
                'RST': bool(flags_value & 0x04),
                'PSH': bool(flags_value & 0x08),
                'ACK': bool(flags_value & 0x10),
                'URG': bool(flags_value & 0x20),
                'ECE': bool(flags_value & 0x40),
                'CWR': bool(flags_value & 0x80)
            }
        except:
            return {}
    
    def read_packets(self):
        """
        Load PCAP and return packets in dictionary format.
        
        Returns:
            list: List of packet dictionaries
        """
        self.load()
        return self.convert_to_dict_format()


# Test function
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pcap_offline_loader.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    print(f"Testing PCAPLoader with: {pcap_file}")
    loader = PCAPLoader(pcap_file)
    
    packets = loader.read_packets()
    
    print(f"\n✓ Loaded {len(packets)} packets")
    
    if packets:
        print("\nFirst packet:")
        first = packets[0]
        for key, value in first.items():
            print(f"  {key}: {value}")
        
        # Count by protocol
        protocols = {}
        for pkt in packets:
            proto = pkt.get('protocol', 'UNKNOWN')
            protocols[proto] = protocols.get(proto, 0) + 1
        
        print(f"\nProtocol distribution:")
        for proto, count in protocols.items():
            print(f"  {proto}: {count}")

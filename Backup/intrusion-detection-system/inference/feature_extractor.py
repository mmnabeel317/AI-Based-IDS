"""
Feature Extraction Module
Extracts 67 statistical features from network packets/flows.
"""

import logging
from typing import List, Dict, Any
import numpy as np
from collections import defaultdict

logger = logging.getLogger(__name__)

# Canonical 67-feature order (NSL-KDD based)
FEATURE_ORDER = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate',
    # Extended features (26 additional)
    'packet_count', 'mean_packet_size', 'std_packet_size',
    'min_packet_size', 'max_packet_size', 'mean_iat', 'std_iat',
    'min_iat', 'max_iat', 'syn_count', 'ack_count', 'psh_count',
    'rst_count', 'fin_count', 'urg_count', 'tcp_window_size_mean',
    'tcp_window_size_std', 'payload_bytes_mean', 'payload_bytes_std',
    'header_bytes_mean', 'fwd_packets', 'bwd_packets',
    'fwd_bytes', 'bwd_bytes', 'flow_bytes_per_sec', 'flow_packets_per_sec'
]

assert len(FEATURE_ORDER) == 67, f"Feature order must have 67 features, got {len(FEATURE_ORDER)}"


class FeatureExtractor:
    """Extracts network flow features from packet data."""
    
    def __init__(self):
        """Initialize feature extractor."""
        self.protocol_map = {
            'tcp': 6, 'udp': 17, 'icmp': 1,
            6: 6, 17: 17, 1: 1  # Allow both string and int
        }
        
        self.service_map = self._build_service_map()
        self.flag_map = self._build_flag_map()
    
    def _build_service_map(self) -> Dict[int, str]:
        """Build port to service mapping."""
        return {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 3306: 'mysql', 5432: 'postgresql',
            6379: 'redis', 27017: 'mongodb', 8080: 'http_alt',
            8443: 'https_alt', 3389: 'rdp', 445: 'smb', 137: 'netbios'
        }
    
    def _build_flag_map(self) -> Dict[str, int]:
        """Build TCP flag mapping."""
        return {
            'S0': 0, 'SF': 1, 'REJ': 2, 'RSTO': 3, 'RSTR': 4,
            'SH': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'RSTOS0': 9, 'OTH': 10
        }
    
    def extract_features(self, flow: Dict[str, Any]) -> np.ndarray:
        """
        Extract 67 features from a flow dictionary.
        
        Args:
            flow: Flow dictionary with packet data
            
        Returns:
            NumPy array of 67 features in canonical order
        """
        features = {}
        
        # Basic features
        features['duration'] = flow.get('duration', 0.0)
        features['protocol_type'] = self._encode_protocol(flow.get('protocol', 6))
        features['service'] = self._encode_service(flow.get('dst_port', 80))
        features['flag'] = self._encode_flag(flow.get('flag', 'SF'))
        
        features['src_bytes'] = flow.get('src_bytes', 0)
        features['dst_bytes'] = flow.get('dst_bytes', 0)
        features['land'] = 1 if flow.get('src_ip') == flow.get('dst_ip') else 0
        features['wrong_fragment'] = flow.get('wrong_fragment', 0)
        features['urgent'] = flow.get('urgent', 0)
        
        # Content features
        features['hot'] = flow.get('hot', 0)
        features['num_failed_logins'] = flow.get('num_failed_logins', 0)
        features['logged_in'] = flow.get('logged_in', 0)
        features['num_compromised'] = flow.get('num_compromised', 0)
        features['root_shell'] = flow.get('root_shell', 0)
        features['su_attempted'] = flow.get('su_attempted', 0)
        features['num_root'] = flow.get('num_root', 0)
        features['num_file_creations'] = flow.get('num_file_creations', 0)
        features['num_shells'] = flow.get('num_shells', 0)
        features['num_access_files'] = flow.get('num_access_files', 0)
        features['num_outbound_cmds'] = flow.get('num_outbound_cmds', 0)
        features['is_host_login'] = flow.get('is_host_login', 0)
        features['is_guest_login'] = flow.get('is_guest_login', 0)
        
        # Time-based traffic features
        features['count'] = flow.get('count', 1)
        features['srv_count'] = flow.get('srv_count', 1)
        features['serror_rate'] = flow.get('serror_rate', 0.0)
        features['srv_serror_rate'] = flow.get('srv_serror_rate', 0.0)
        features['rerror_rate'] = flow.get('rerror_rate', 0.0)
        features['srv_rerror_rate'] = flow.get('srv_rerror_rate', 0.0)
        features['same_srv_rate'] = flow.get('same_srv_rate', 1.0)
        features['diff_srv_rate'] = flow.get('diff_srv_rate', 0.0)
        features['srv_diff_host_rate'] = flow.get('srv_diff_host_rate', 0.0)
        
        # Host-based traffic features
        features['dst_host_count'] = flow.get('dst_host_count', 1)
        features['dst_host_srv_count'] = flow.get('dst_host_srv_count', 1)
        features['dst_host_same_srv_rate'] = flow.get('dst_host_same_srv_rate', 1.0)
        features['dst_host_diff_srv_rate'] = flow.get('dst_host_diff_srv_rate', 0.0)
        features['dst_host_same_src_port_rate'] = flow.get('dst_host_same_src_port_rate', 1.0)
        features['dst_host_srv_diff_host_rate'] = flow.get('dst_host_srv_diff_host_rate', 0.0)
        features['dst_host_serror_rate'] = flow.get('dst_host_serror_rate', 0.0)
        features['dst_host_srv_serror_rate'] = flow.get('dst_host_srv_serror_rate', 0.0)
        features['dst_host_rerror_rate'] = flow.get('dst_host_rerror_rate', 0.0)
        features['dst_host_srv_rerror_rate'] = flow.get('dst_host_srv_rerror_rate', 0.0)
        
        # Extended features - compute from packets if available
        packets = flow.get('packets', [])
        if packets:
            features.update(self._compute_extended_features(packets, flow))
        else:
            # Fallback values if packets not available
            features.update(self._default_extended_features())
        
        # Convert to ordered array
        feature_vector = np.array([features[fname] for fname in FEATURE_ORDER], dtype=np.float32)
        
        # Validate
        if len(feature_vector) != 67:
            raise ValueError(f"Feature vector must have 67 elements, got {len(feature_vector)}")
        
        return feature_vector
    
    def _encode_protocol(self, protocol) -> int:
        """Encode protocol to integer."""
        if isinstance(protocol, int):
            return protocol
        return self.protocol_map.get(str(protocol).lower(), 6)
    
    def _encode_service(self, port: int) -> int:
        """Encode service port to integer category."""
        # Use port number directly, or map to service code
        if port in self.service_map:
            return hash(self.service_map[port]) % 100
        return port % 100
    
    def _encode_flag(self, flag: str) -> int:
        """Encode TCP flag string to integer."""
        return self.flag_map.get(flag, 10)  # Default to OTH
    
    def _compute_extended_features(self, packets: List[Dict], flow: Dict) -> Dict[str, float]:
        """Compute extended statistical features from packets."""
        ext_features = {}
        
        packet_sizes = [pkt.get('length', 0) for pkt in packets]
        timestamps = [pkt.get('timestamp', 0) for pkt in packets]
        
        # Packet statistics
        ext_features['packet_count'] = len(packets)
        ext_features['mean_packet_size'] = np.mean(packet_sizes) if packet_sizes else 0
        ext_features['std_packet_size'] = np.std(packet_sizes) if len(packet_sizes) > 1 else 0
        ext_features['min_packet_size'] = min(packet_sizes) if packet_sizes else 0
        ext_features['max_packet_size'] = max(packet_sizes) if packet_sizes else 0
        
        # Inter-arrival times
        if len(timestamps) > 1:
            iats = np.diff(sorted(timestamps))
            ext_features['mean_iat'] = np.mean(iats)
            ext_features['std_iat'] = np.std(iats)
            ext_features['min_iat'] = np.min(iats)
            ext_features['max_iat'] = np.max(iats)
        else:
            ext_features['mean_iat'] = 0
            ext_features['std_iat'] = 0
            ext_features['min_iat'] = 0
            ext_features['max_iat'] = 0
        
        # TCP flag counts
        ext_features['syn_count'] = sum(1 for pkt in packets if pkt.get('syn', False))
        ext_features['ack_count'] = sum(1 for pkt in packets if pkt.get('ack', False))
        ext_features['psh_count'] = sum(1 for pkt in packets if pkt.get('psh', False))
        ext_features['rst_count'] = sum(1 for pkt in packets if pkt.get('rst', False))
        ext_features['fin_count'] = sum(1 for pkt in packets if pkt.get('fin', False))
        ext_features['urg_count'] = sum(1 for pkt in packets if pkt.get('urg', False))
        
        # TCP window sizes
        window_sizes = [pkt.get('window', 0) for pkt in packets if 'window' in pkt]
        ext_features['tcp_window_size_mean'] = np.mean(window_sizes) if window_sizes else 0
        ext_features['tcp_window_size_std'] = np.std(window_sizes) if len(window_sizes) > 1 else 0
        
        # Payload statistics
        payload_sizes = [pkt.get('payload_length', 0) for pkt in packets]
        ext_features['payload_bytes_mean'] = np.mean(payload_sizes) if payload_sizes else 0
        ext_features['payload_bytes_std'] = np.std(payload_sizes) if len(payload_sizes) > 1 else 0
        
        # Header bytes (estimate)
        ext_features['header_bytes_mean'] = np.mean([p - pl for p, pl in zip(packet_sizes, payload_sizes)])
        
        # Directional features
        ext_features['fwd_packets'] = sum(1 for pkt in packets if pkt.get('direction') == 'fwd')
        ext_features['bwd_packets'] = sum(1 for pkt in packets if pkt.get('direction') == 'bwd')
        ext_features['fwd_bytes'] = sum(pkt.get('length', 0) for pkt in packets if pkt.get('direction') == 'fwd')
        ext_features['bwd_bytes'] = sum(pkt.get('length', 0) for pkt in packets if pkt.get('direction') == 'bwd')
        
        # Flow rates
        duration = flow.get('duration', 1.0)
        if duration > 0:
            ext_features['flow_bytes_per_sec'] = sum(packet_sizes) / duration
            ext_features['flow_packets_per_sec'] = len(packets) / duration
        else:
            ext_features['flow_bytes_per_sec'] = 0
            ext_features['flow_packets_per_sec'] = 0
        
        return ext_features
    
    def _default_extended_features(self) -> Dict[str, float]:
        """Return default values for extended features when packets unavailable."""
        return {
            'packet_count': 1, 'mean_packet_size': 60, 'std_packet_size': 0,
            'min_packet_size': 60, 'max_packet_size': 60,
            'mean_iat': 0, 'std_iat': 0, 'min_iat': 0, 'max_iat': 0,
            'syn_count': 1, 'ack_count': 1, 'psh_count': 0,
            'rst_count': 0, 'fin_count': 0, 'urg_count': 0,
            'tcp_window_size_mean': 8192, 'tcp_window_size_std': 0,
            'payload_bytes_mean': 0, 'payload_bytes_std': 0,
            'header_bytes_mean': 40,
            'fwd_packets': 1, 'bwd_packets': 0,
            'fwd_bytes': 60, 'bwd_bytes': 0,
            'flow_bytes_per_sec': 60, 'flow_packets_per_sec': 1
        }

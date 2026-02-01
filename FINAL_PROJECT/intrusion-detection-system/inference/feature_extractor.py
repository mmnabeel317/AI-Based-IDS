"""
Feature Extractor for Network Intrusion Detection
Extracts 67 features matching CIC-IDS2018 training data
"""

import numpy as np
from collections import defaultdict


class FeatureExtractor:
    """
    Extracts exactly 67 network flow features compatible with trained model.
    Features must match the training data structure exactly.
    """
    
    def __init__(self):
        """Initialize the feature extractor"""
        self.feature_names = self._get_feature_names()
        
    def _get_feature_names(self):
        """Returns the ordered list of 67 feature names matching training"""
        return [
            'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
            'total_length_fwd_packets', 'total_length_bwd_packets',
            'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean',
            'fwd_packet_length_std', 'bwd_packet_length_max', 'bwd_packet_length_min',
            'bwd_packet_length_mean', 'bwd_packet_length_std', 'flow_bytes_per_s',
            'flow_packets_per_s', 'flow_iat_mean', 'flow_iat_std', 'flow_iat_max',
            'flow_iat_min', 'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std',
            'fwd_iat_max', 'fwd_iat_min', 'bwd_iat_total', 'bwd_iat_mean',
            'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags',
            'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags', 'fwd_header_length',
            'bwd_header_length', 'fwd_packets_per_s', 'bwd_packets_per_s',
            'min_packet_length', 'max_packet_length', 'packet_length_mean',
            'packet_length_std', 'packet_length_variance', 'fin_flag_count',
            'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 'ack_flag_count',
            'urg_flag_count', 'cwe_flag_count', 'ece_flag_count', 'down_up_ratio',
            'avg_packet_size', 'avg_fwd_segment_size', 'avg_bwd_segment_size',
            'fwd_header_length_mean', 'fwd_avg_packets_bulk', 'fwd_avg_bulk_rate',
            'bwd_avg_bytes_bulk', 'bwd_avg_packets_bulk', 'bwd_avg_bulk_rate',
            'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets',
            'subflow_bwd_bytes', 'init_win_bytes_forward', 'init_win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward'
        ]
    
    def extract_features(self, flow_data):
        """
        Extract 67 features from a network flow.
        
        Args:
            flow_data (dict): Must contain:
                - 'packets': list of all packets
                - 'forward_packets': list of forward direction packets  
                - 'backward_packets': list of backward direction packets
                - 'flow_start_time': float timestamp
                - 'flow_last_seen': float timestamp
        
        Returns:
            np.ndarray: Array of 67 features
        """
        try:
            # Get packet lists
            packets = flow_data.get('packets', [])
            fwd_packets = flow_data.get('forward_packets', [])
            bwd_packets = flow_data.get('backward_packets', [])
            
            if not packets:
                return np.zeros(67, dtype=np.float64)
            
            # Get timing
            flow_start = flow_data.get('flow_start_time', 0)
            flow_end = flow_data.get('flow_last_seen', flow_start)
            
            # Extract features
            features = self._calculate_features(
                packets, fwd_packets, bwd_packets, flow_start, flow_end
            )
            
            # Clean features
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
            
            return features
            
        except Exception as e:
            print(f"ERROR in feature extraction: {e}")
            import traceback
            traceback.print_exc()
            return np.zeros(67, dtype=np.float64)
    
    def _calculate_features(self, packets, fwd_packets, bwd_packets, flow_start, flow_end):
        """Calculate all 67 features"""
        features = np.zeros(67, dtype=np.float64)
        
        # Helper for safe stats
        def safe_stat(data, func, default=0.0):
            try:
                if len(data) == 0:
                    return default
                result = func(data)
                return result if np.isfinite(result) else default
            except:
                return default
        
        # 0: Flow duration (microseconds)
        duration_s = max(flow_end - flow_start, 0)
        features[0] = duration_s * 1e6
        
        # 1-2: Packet counts
        features[1] = len(fwd_packets)
        features[2] = len(bwd_packets)
        
        # 3-4: Total bytes
        fwd_lengths = [p.get('length', p.get('size', 0)) for p in fwd_packets]
        bwd_lengths = [p.get('length', p.get('size', 0)) for p in bwd_packets]
        features[3] = sum(fwd_lengths)
        features[4] = sum(bwd_lengths)
        
        # 5-8: Forward packet length stats
        features[5] = safe_stat(fwd_lengths, max, 0)
        features[6] = safe_stat(fwd_lengths, min, 0)
        features[7] = safe_stat(fwd_lengths, np.mean, 0)
        features[8] = safe_stat(fwd_lengths, np.std, 0)
        
        # 9-12: Backward packet length stats
        features[9] = safe_stat(bwd_lengths, max, 0)
        features[10] = safe_stat(bwd_lengths, min, 0)
        features[11] = safe_stat(bwd_lengths, np.mean, 0)
        features[12] = safe_stat(bwd_lengths, np.std, 0)
        
        # 13-14: Flow byte/s and packet/s
        if duration_s > 0:
            features[13] = (features[3] + features[4]) / duration_s
            features[14] = (features[1] + features[2]) / duration_s
        
        # 15-19: Flow IAT (inter-arrival times)
        timestamps = [p.get('timestamp', 0) for p in packets]
        iats = []
        if len(timestamps) > 1:
            iats = [(timestamps[i+1] - timestamps[i]) * 1e6 for i in range(len(timestamps)-1)]
        
        features[15] = safe_stat(iats, np.mean, 0)
        features[16] = safe_stat(iats, np.std, 0)
        features[17] = safe_stat(iats, max, 0)
        features[18] = safe_stat(iats, min, 0)
        
        # 19-23: Forward IAT
        fwd_times = [p.get('timestamp', 0) for p in fwd_packets]
        fwd_iats = []
        if len(fwd_times) > 1:
            fwd_iats = [(fwd_times[i+1] - fwd_times[i]) * 1e6 for i in range(len(fwd_times)-1)]
        
        features[19] = sum(fwd_iats) if fwd_iats else 0
        features[20] = safe_stat(fwd_iats, np.mean, 0)
        features[21] = safe_stat(fwd_iats, np.std, 0)
        features[22] = safe_stat(fwd_iats, max, 0)
        features[23] = safe_stat(fwd_iats, min, 0)
        
        # 24-28: Backward IAT
        bwd_times = [p.get('timestamp', 0) for p in bwd_packets]
        bwd_iats = []
        if len(bwd_times) > 1:
            bwd_iats = [(bwd_times[i+1] - bwd_times[i]) * 1e6 for i in range(len(bwd_times)-1)]
        
        features[24] = sum(bwd_iats) if bwd_iats else 0
        features[25] = safe_stat(bwd_iats, np.mean, 0)
        features[26] = safe_stat(bwd_iats, np.std, 0)
        features[27] = safe_stat(bwd_iats, max, 0)
        features[28] = safe_stat(bwd_iats, min, 0)
        
        # 29-32: PSH and URG flags
        features[29] = sum(1 for p in fwd_packets if p.get('flags', {}).get('PSH', False))
        features[30] = sum(1 for p in bwd_packets if p.get('flags', {}).get('PSH', False))
        features[31] = sum(1 for p in fwd_packets if p.get('flags', {}).get('URG', False))
        features[32] = sum(1 for p in bwd_packets if p.get('flags', {}).get('URG', False))
        
        # 33-34: Header lengths (TCP=20, UDP=8, default=20)
        features[33] = sum(p.get('header_length', 20) for p in fwd_packets)
        features[34] = sum(p.get('header_length', 20) for p in bwd_packets)
        
        # 35-36: Packets per second
        if duration_s > 0:
            features[35] = features[1] / duration_s
            features[36] = features[2] / duration_s
        
        # 37-41: Overall packet length stats
        all_lengths = fwd_lengths + bwd_lengths
        features[37] = safe_stat(all_lengths, min, 0)
        features[38] = safe_stat(all_lengths, max, 0)
        features[39] = safe_stat(all_lengths, np.mean, 0)
        features[40] = safe_stat(all_lengths, np.std, 0)
        features[41] = features[40] ** 2  # variance
        
        # 42-49: TCP flags
        features[42] = sum(1 for p in packets if p.get('flags', {}).get('FIN', False))
        features[43] = sum(1 for p in packets if p.get('flags', {}).get('SYN', False))
        features[44] = sum(1 for p in packets if p.get('flags', {}).get('RST', False))
        features[45] = sum(1 for p in packets if p.get('flags', {}).get('PSH', False))
        features[46] = sum(1 for p in packets if p.get('flags', {}).get('ACK', False))
        features[47] = sum(1 for p in packets if p.get('flags', {}).get('URG', False))
        features[48] = sum(1 for p in packets if p.get('flags', {}).get('CWR', False))
        features[49] = sum(1 for p in packets if p.get('flags', {}).get('ECE', False))
        
        # 50: Down/Up ratio
        if features[3] > 0:
            features[50] = features[4] / features[3]
        
        # 51-53: Average segment sizes
        total_packets = features[1] + features[2]
        if total_packets > 0:
            features[51] = (features[3] + features[4]) / total_packets
        if features[1] > 0:
            features[52] = features[3] / features[1]
        if features[2] > 0:
            features[53] = features[4] / features[2]
        
        # 54: Forward header length average
        if features[1] > 0:
            features[54] = features[33] / features[1]
        
        # 55-59: Bulk features (simplified - set to 0 for now)
        features[55] = 0
        features[56] = 0
        features[57] = 0
        features[58] = 0
        features[59] = 0
        
        # 60-63: Subflow features (same as total for single flow)
        features[60] = features[1]
        features[61] = features[3]
        features[62] = features[2]
        features[63] = features[4]
        
        # 64-65: Initial window bytes
        features[64] = fwd_packets[0].get('window', 8192) if fwd_packets else 8192
        features[65] = bwd_packets[0].get('window', 8192) if bwd_packets else 8192
        
        # 66: Active data packets forward
        features[66] = sum(1 for p in fwd_packets if p.get('length', 0) > 0)
        
        return features

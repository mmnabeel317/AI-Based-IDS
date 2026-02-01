"""
Demo Data Generator
Generates synthetic flows and packets for testing.
"""

import random
import time
from typing import List, Dict
import numpy as np


def generate_synthetic_flow() -> Dict:
    """
    Generate a synthetic network flow for testing.
    
    Returns:
        Flow dictionary with all required fields
    """
    # Random 5-tuple
    src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    dst_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([22, 80, 443, 3306, 8080, 5432])
    protocol = random.choice([6, 17])  # TCP or UDP
    
    # Basic features
    duration = random.uniform(0.1, 120.0)
    src_bytes = random.randint(0, 100000)
    dst_bytes = random.randint(0, 100000)
    
    flow = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'duration': duration,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        
        # Content features
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': random.choice([0, 1]),
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        
        # Time-based features
        'count': random.randint(1, 100),
        'srv_count': random.randint(1, 50),
        'serror_rate': random.uniform(0, 1),
        'srv_serror_rate': random.uniform(0, 1),
        'rerror_rate': random.uniform(0, 1),
        'srv_rerror_rate': random.uniform(0, 1),
        'same_srv_rate': random.uniform(0, 1),
        'diff_srv_rate': random.uniform(0, 1),
        'srv_diff_host_rate': random.uniform(0, 1),
        
        # Host-based features
        'dst_host_count': random.randint(1, 255),
        'dst_host_srv_count': random.randint(1, 255),
        'dst_host_same_srv_rate': random.uniform(0, 1),
        'dst_host_diff_srv_rate': random.uniform(0, 1),
        'dst_host_same_src_port_rate': random.uniform(0, 1),
        'dst_host_srv_diff_host_rate': random.uniform(0, 1),
        'dst_host_serror_rate': random.uniform(0, 1),
        'dst_host_srv_serror_rate': random.uniform(0, 1),
        'dst_host_rerror_rate': random.uniform(0, 1),
        'dst_host_srv_rerror_rate': random.uniform(0, 1),
        
        # Packets for extended feature extraction
        'packets': generate_synthetic_packets(count=random.randint(5, 20))
    }
    
    return flow


def generate_synthetic_packets(count: int = 10) -> List[Dict]:
    """
    Generate synthetic packet list.
    
    Args:
        count: Number of packets to generate
        
    Returns:
        List of packet dictionaries
    """
    packets = []
    base_time = time.time()
    
    for i in range(count):
        packet = {
            'timestamp': base_time + i * random.uniform(0.001, 0.1),
            'length': random.randint(40, 1500),
            'payload_length': random.randint(0, 1460),
            'direction': random.choice(['fwd', 'bwd']),
            'syn': i == 0,  # First packet is SYN
            'ack': i > 0,
            'fin': i == count - 1,  # Last packet is FIN
            'rst': False,
            'psh': random.choice([True, False]),
            'urg': False,
            'window': random.randint(1024, 65535)
        }
        packets.append(packet)
    
    return packets


def generate_attack_flow(attack_type: str) -> Dict:
    """
    Generate a synthetic flow with attack characteristics.
    
    Args:
        attack_type: Type of attack (DoS, Probe, R2L, U2R)
        
    Returns:
        Flow dictionary
    """
    flow = generate_synthetic_flow()
    
    if attack_type == 'DoS':
        # High packet rate, low duration
        flow['count'] = random.randint(500, 2000)
        flow['duration'] = random.uniform(0.1, 5.0)
        flow['src_bytes'] = random.randint(100000, 1000000)
        flow['same_srv_rate'] = 1.0
        flow['srv_count'] = flow['count']
        
    elif attack_type == 'Probe':
        # Multiple connections to different services
        flow['srv_count'] = random.randint(1, 5)
        flow['diff_srv_rate'] = random.uniform(0.8, 1.0)
        flow['dst_host_srv_count'] = random.randint(10, 100)
        flow['serror_rate'] = random.uniform(0.5, 1.0)
        
    elif attack_type == 'R2L':
        # Failed login attempts
        flow['num_failed_logins'] = random.randint(3, 10)
        flow['logged_in'] = 0
        flow['count'] = random.randint(5, 20)
        
    elif attack_type == 'U2R':
        # Privilege escalation indicators
        flow['num_compromised'] = random.randint(1, 5)
        flow['root_shell'] = 1
        flow['su_attempted'] = 1
        flow['num_root'] = random.randint(1, 3)
    
    return flow


if __name__ == '__main__':
    # Demo: generate and print sample flows
    print("Normal flow:")
    print(generate_synthetic_flow())
    
    print("\nDoS attack flow:")
    print(generate_attack_flow('DoS'))

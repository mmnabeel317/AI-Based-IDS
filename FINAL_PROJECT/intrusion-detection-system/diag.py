# test_traffic_generator.py
from scapy.all import *
import random

packets = []

# Benign: Normal HTTP session
for i in range(10):
    pkt = IP(src="192.168.1.100", dst="8.8.8.8")/TCP(sport=50000+i, dport=80)/("GET / HTTP/1.1")
    packets.append(pkt)

# DoS: High-rate SYN flood
for i in range(100):
    pkt = IP(src=f"10.0.0.{random.randint(1,255)}", dst="192.168.1.1")/TCP(sport=random.randint(1024,65535), dport=80, flags="S")
    packets.append(pkt)

# Bot: C&C communication
for i in range(20):
    pkt = IP(src="192.168.1.50", dst="evil-server.com")/TCP(sport=54321, dport=6667)/("JOIN #botnet")
    packets.append(pkt)

wrpcap("test_attacks.pcap", packets)
print("✓ Generated test_attacks.pcap")

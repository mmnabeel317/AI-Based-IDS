"""Test packet capture directly with Scapy"""
import sys
from scapy.all import sniff, get_if_list, conf

print("="*60)
print("Scapy Packet Capture Test")
print("="*60)

# List interfaces
print("\n1. Available interfaces:")
try:
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"   [{i}] {iface}")
except Exception as e:
    print(f"   ERROR: {e}")

# Test default interface
print(f"\n2. Default interface: {conf.iface}")

# Try capturing on default
print("\n3. Attempting capture (10 packets, 10 second timeout)...")
print("   Generate some traffic (open a browser, ping something)...")

try:
    packets = sniff(count=10, timeout=10)
    print(f"\n   ✓ Captured {len(packets)} packets!")
    
    if packets:
        print("\n4. Sample packet info:")
        pkt = packets[0]
        print(f"   Type: {type(pkt)}")
        print(f"   Summary: {pkt.summary()}")
    else:
        print("\n   ⚠ No packets captured")
        print("   Possible causes:")
        print("   - Not running as Administrator")
        print("   - No network traffic")
        print("   - Wrong interface selected")
        print("   - Npcap not configured correctly")
        
except PermissionError:
    print("\n   ✗ Permission denied!")
    print("   → Run as Administrator")
except Exception as e:
    print(f"\n   ✗ Capture failed: {e}")

print("\n" + "="*60)

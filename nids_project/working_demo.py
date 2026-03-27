#!/usr/bin/env python3
"""Working NIDS Demo - Shows detection with PCAP analysis"""

import sys
import os
import time
import glob
sys.path.insert(0, 'src')

from detection import DetectionEngine
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw

print("\n" + "="*70)
print(" NIDS WORKING DEMO")
print("="*70)

# Initialize detector
detector = DetectionEngine([])
detector.set_confidence_threshold(30)
detector.config.ALERT_COOLDOWN = 0

print("\n[1] Analyzing existing PCAP files...\n")

# Find all PCAP files
pcap_files = sorted(glob.glob("data/attacks/*.pcap"))[-5:]  # Last 5 files

if not pcap_files:
    print("  No PCAP files found. Please generate attacks first:")
    print("  python scripts/attack_generator.py --attack sql_injection")
    sys.exit(1)

for pcap_file in pcap_files:
    print(f"  Analyzing: {os.path.basename(pcap_file)}")
    
    # Load packets
    packets = rdpcap(pcap_file)
    total_packets = min(len(packets), 20)  # Analyze first 20 packets
    
    detections = 0
    alert_types = set()
    
    for pkt in packets[:total_packets]:
        if IP not in pkt:
            continue
        
        # Extract payload
        payload = bytes(pkt[Raw]) if Raw in pkt else b''
        
        # Normalize packet
        pkt_dict = {
            'src': pkt[IP].src,
            'dst': pkt[IP].dst,
            'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'ICMP',
            'src_port': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            'dst_port': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            'flags': pkt[TCP].sprintf('%flags%') if TCP in pkt else '',
            'payload': payload,
            'timestamp': pkt.time,
        }
        
        alerts = detector.process_packet(pkt_dict)
        if alerts:
            detections += len(alerts)
            for alert in alerts:
                alert_types.add(alert['type'])
    
    print(f"    Packets: {total_packets} | Detections: {detections} | Types: {', '.join(list(alert_types)[:3])}")
    if detections > 0:
        print(f"    ✓ Detection successful!")

print("\n" + "="*70)
print("✓ Demo complete!")
print("="*70)

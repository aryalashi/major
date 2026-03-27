#!/usr/bin/env python3
"""Simple NIDS Demo - Shows detection in action"""

import sys
import os
import time
sys.path.insert(0, 'src')
sys.path.insert(0, 'scripts')

from detection import DetectionEngine
from attack_generator import AttackGenerator, AttackConfig
from scapy.all import IP, TCP, UDP, ICMP, Raw

print("\n" + "="*70)
print(" NIDS DETECTION DEMO")
print("="*70)

# Initialize
detector = DetectionEngine([])
detector.set_confidence_threshold(30)
detector.config.ALERT_COOLDOWN = 0  # Show all detections

generator = AttackGenerator("data/attacks")

# Test attacks
attacks = [
    ("SQL Injection", "sql_injection"),
    ("XSS Attack", "xss"),
    ("Command Injection", "command_injection"),
]

print("\n[1] Generating and detecting attacks...\n")

for name, attack_type in attacks:
    print(f"  Testing: {name}")
    
    # Generate attack
    config = AttackConfig(
        attack_type=attack_type,
        duration_seconds=2,
        packet_rate=20,
        source_ip="192.168.1.100",
        target_ip="10.0.0.1"
    )
    
    packets, pcap, rule = generator.generate_and_log_attack(config, dry_run=True)
    
    # Detect
    detections = 0
    for pkt in packets[:10]:  # Check first 10 packets
        # Extract payload properly
        payload = b''
        if Raw in pkt:
            payload = bytes(pkt[Raw])
        
        pkt_dict = {
            'src': pkt[IP].src if IP in pkt else '192.168.1.100',
            'dst': pkt[IP].dst if IP in pkt else '10.0.0.1',
            'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'ICMP',
            'flags': pkt[TCP].sprintf('%flags%') if TCP in pkt else '',
            'dst_port': pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
            'src_port': pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
            'payload': payload,
            'timestamp': time.time(),
        }
        alerts = detector.process_packet(pkt_dict)
        if alerts:
            detections += len(alerts)
            for alert in alerts[:2]:  # Show first 2 alerts
                print(f"      ✓ {alert['type']} ({alert['confidence']:.0f}%)")
    
    detection_rate = (detections / len(packets[:10])) * 100
    print(f"    → Detection rate: {detection_rate:.0f}% ({detections}/{len(packets[:10])} packets)\n")

print("="*70)
print("✓ Demo complete! Check data/attacks/ for PCAP files")
print("="*70)

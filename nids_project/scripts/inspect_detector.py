#!/usr/bin/env python3
"""Inspect what the advanced detector returns"""

from advanced_detection_engine import AdvancedSignatureDetector
import json

# Initialize detector
detector = AdvancedSignatureDetector()

# Test packet with SQL injection
test_packet = {
    'src_ip': '192.168.1.100',
    'dst_ip': '10.0.0.1',
    'protocol': 6,  # TCP
    'src_port': 54321,
    'dst_port': 80,
    'flags': 'PA',
    'payload': b"SELECT * FROM users WHERE id=1 OR 1=1--",
    'timestamp': 1234567890,
}

print("[*] Testing advanced detector directly...")
alerts = detector.detect_attack(test_packet)

print(f"\nAlerts returned: {len(alerts)}")
for i, alert in enumerate(alerts):
    print(f"\nAlert {i+1}:")
    for key, value in alert.items():
        print(f"  {key}: {value}")
    
# Check what _detect_payload_attacks returns
print("\n[*] Testing payload detection specifically...")
payload_alerts = detector._detect_payload_attacks(test_packet)
print(f"Payload alerts: {len(payload_alerts)}")
for alert in payload_alerts:
    print(f"  {alert['attack']} - {alert['confidence']:.1f}%")

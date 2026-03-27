#!/usr/bin/env python3
"""Quick test to verify detection engine works"""

from detection import DetectionEngine
import time

# Initialize detector
detector = DetectionEngine([])

# Test SQL Injection packet
test_packet = {
    'src': '192.168.1.50',
    'dst': '192.168.1.100',
    'protocol': 'TCP',
    'flags': 'PA',
    'dst_port': 80,
    'src_port': 54325,
    'payload': b"SELECT * FROM users WHERE id=1 OR 1=1--",
    'timestamp': time.time(),
}

print("[*] Testing SQL Injection detection...")
alerts = detector.process_packet(test_packet)

if alerts:
    for alert in alerts:
        print(f"[✓] DETECTED: {alert['type']} (Confidence: {alert['confidence']:.1f}%)")
else:
    print("[✗] No detection - check detection engine configuration")

# Print detector statistics
print(f"\n[*] Detector stats: {detector.get_stats()}")

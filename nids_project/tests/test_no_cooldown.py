#!/usr/bin/env python3
"""Test detection with cooldown disabled"""

from detection import DetectionEngine
import time

# Create detector
detector = DetectionEngine([])

# Disable cooldown for testing
detector.config.ALERT_COOLDOWN = 0
detector.set_confidence_threshold(30)

print("[*] Detector initialized (cooldown disabled)")

# Test packets
test_cases = [
    {
        'name': 'SQL Injection',
        'packet': {
            'src': '192.168.1.100',
            'dst': '10.0.0.1',
            'protocol': 'TCP',
            'flags': 'PA',
            'dst_port': 80,
            'src_port': 54325,
            'payload': b"SELECT * FROM users WHERE id=1 OR 1=1--",
            'timestamp': time.time(),
        }
    },
    {
        'name': 'XSS Attack',
        'packet': {
            'src': '192.168.1.100',
            'dst': '10.0.0.1',
            'protocol': 'TCP',
            'flags': 'PA',
            'dst_port': 80,
            'src_port': 54326,
            'payload': b"<img src=x onerror=alert('XSS')>",
            'timestamp': time.time(),
        }
    },
    {
        'name': 'Command Injection',
        'packet': {
            'src': '192.168.1.100',
            'dst': '10.0.0.1',
            'protocol': 'TCP',
            'flags': 'PA',
            'dst_port': 80,
            'src_port': 54327,
            'payload': b"; cat /etc/passwd",
            'timestamp': time.time(),
        }
    }
]

for test in test_cases:
    print(f"\n{'='*60}")
    print(f"Testing: {test['name']}")
    print(f"{'='*60}")
    
    alerts = detector.process_packet(test['packet'])
    
    if alerts:
        print(f"Detected {len(alerts)} alert(s):")
        for alert in alerts:
            print(f"  ✓ {alert['type']:<35} Confidence: {alert['confidence']:.0f}% | Severity: {alert['severity']}")
    else:
        print("  ✗ No detection")
    
    time.sleep(0.5)

print(f"\n{'='*60}")
print("Summary:")
print(f"{'='*60}")
stats = detector.get_stats()
print(f"Packets processed: {stats['total_packets']}")
print(f"Alerts generated: {stats['total_alerts']}")
print(f"Alert rate: {stats['total_alerts']/stats['total_packets']*100:.1f}%")

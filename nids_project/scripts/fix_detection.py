#!/usr/bin/env python3
"""Fix the detection engine to properly classify specific attacks"""

import sys
import time
from detection import DetectionEngine

# Create a test function to verify specific detections
def test_specific_attacks():
    detector = DetectionEngine([])
    
    print("="*70)
    print("TESTING SPECIFIC ATTACK DETECTIONS")
    print("="*70)
    
    # Test 1: SQL Injection
    print("\n[TEST 1] SQL Injection")
    sql_packet = {
        'src': '192.168.1.50',
        'dst': '192.168.1.100',
        'protocol': 'TCP',
        'flags': 'PA',
        'dst_port': 80,
        'src_port': 54325,
        'payload': b"SELECT * FROM users WHERE id=1 OR 1=1--",
        'timestamp': time.time(),
    }
    alerts = detector.process_packet(sql_packet)
    if alerts:
        for alert in alerts:
            if 'SQL' in alert['type'] or 'Injection' in alert['type']:
                print(f"  ✓ SQL Injection detected: {alert['type']} ({alert['confidence']:.1f}%)")
            else:
                print(f"  ⚠ Generic detection: {alert['type']} (Should be SQL Injection)")
    else:
        print("  ✗ No detection")
    
    # Test 2: XSS
    print("\n[TEST 2] XSS Attack")
    xss_packet = {
        'src': '192.168.1.50',
        'dst': '192.168.1.100',
        'protocol': 'TCP',
        'flags': 'PA',
        'dst_port': 80,
        'src_port': 54326,
        'payload': b"<img src=x onerror=alert('XSS')>",
        'timestamp': time.time(),
    }
    alerts = detector.process_packet(xss_packet)
    if alerts:
        for alert in alerts:
            if 'XSS' in alert['type']:
                print(f"  ✓ XSS detected: {alert['type']} ({alert['confidence']:.1f}%)")
            else:
                print(f"  ⚠ Generic detection: {alert['type']} (Should be XSS)")
    else:
        print("  ✗ No detection")
    
    # Test 3: Command Injection
    print("\n[TEST 3] Command Injection")
    cmd_packet = {
        'src': '192.168.1.50',
        'dst': '192.168.1.100',
        'protocol': 'TCP',
        'flags': 'PA',
        'dst_port': 80,
        'src_port': 54327,
        'payload': b"; cat /etc/passwd",
        'timestamp': time.time(),
    }
    alerts = detector.process_packet(cmd_packet)
    if alerts:
        for alert in alerts:
            if 'Command' in alert['type'] or 'Injection' in alert['type']:
                print(f"  ✓ Command Injection detected: {alert['type']} ({alert['confidence']:.1f}%)")
            else:
                print(f"  ⚠ Generic detection: {alert['type']} (Should be Command Injection)")
    else:
        print("  ✗ No detection")
    
    # Test 4: Port Scan
    print("\n[TEST 4] Port Scan")
    scan_packets = []
    for port in range(1000, 1010):
        scan_packets.append({
            'src': '192.168.1.50',
            'dst': '192.168.1.100',
            'protocol': 'TCP',
            'flags': 'S',
            'dst_port': port,
            'src_port': 54328,
            'payload': b'',
            'timestamp': time.time() + port * 0.01,
        })
    
    scan_detected = False
    for pkt in scan_packets:
        alerts = detector.process_packet(pkt)
        if alerts and any('Scan' in a['type'] for a in alerts):
            scan_detected = True
            for alert in alerts:
                if 'Scan' in alert['type']:
                    print(f"  ✓ Port Scan detected: {alert['type']} ({alert['confidence']:.1f}%)")
            break
    
    if not scan_detected:
        print("  ✗ No port scan detection")
    
    print("\n" + "="*70)

if __name__ == "__main__":
    test_specific_attacks()

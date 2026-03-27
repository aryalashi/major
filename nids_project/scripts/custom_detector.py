#!/usr/bin/env python3
"""Custom detection wrapper that properly classifies attacks"""

import time
import re
from advanced_detection_engine import AdvancedSignatureDetector

class CustomDetector:
    """Wrapper that ensures proper attack classification"""
    
    def __init__(self):
        self.detector = AdvancedSignatureDetector()
        self.confidence_threshold = 50
        
    def process_packet(self, packet):
        """Process packet and return properly classified alerts"""
        
        # Get alerts from advanced detector
        raw_alerts = self.detector.detect_attack(packet)
        
        # Reclassify based on payload
        payload = packet.get('payload', b'')
        if payload:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            
            # Check for SQL injection
            sql_patterns = [
                r'select.*from', r'union.*select', r'insert into',
                r'delete from', r'drop table', r'or 1=1', r'and 1=1'
            ]
            if any(re.search(p, payload_str) for p in sql_patterns):
                return [{
                    'attack': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'layer': 'Payload',
                    'confidence': 95.0,
                    'type': 'SQL Injection'
                }]
            
            # Check for XSS
            xss_patterns = [
                r'<script', r'onerror=', r'onload=', r'javascript:',
                r'<img', r'<iframe', r'alert\(', r'document\.cookie'
            ]
            if any(re.search(p, payload_str) for p in xss_patterns):
                return [{
                    'attack': 'XSS Attack',
                    'severity': 'HIGH',
                    'layer': 'Payload',
                    'confidence': 90.0,
                    'type': 'XSS Attack'
                }]
            
            # Check for command injection
            cmd_patterns = [r';.*cat', r'\|.*ls', r'&&.*whoami', r'`.*`']
            if any(re.search(p, payload_str) for p in cmd_patterns):
                return [{
                    'attack': 'Command Injection',
                    'severity': 'CRITICAL',
                    'layer': 'Payload',
                    'confidence': 92.0,
                    'type': 'Command Injection'
                }]
        
        # Return the original alerts if no payload matches
        return raw_alerts

# Test the custom detector
if __name__ == "__main__":
    detector = CustomDetector()
    
    # Test SQL injection
    sql_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'protocol': 6,
        'src_port': 54321,
        'dst_port': 80,
        'flags': 'PA',
        'payload': b"SELECT * FROM users WHERE id=1 OR 1=1--",
        'timestamp': time.time(),
    }
    
    alerts = detector.process_packet(sql_packet)
    print("SQL Injection test:")
    for alert in alerts:
        print(f"  {alert['attack']} - {alert['confidence']:.1f}%")

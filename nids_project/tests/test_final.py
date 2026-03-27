#!/usr/bin/env python3
"""Final NIDS test with proper multi-packet detection"""

import os
import sys
import time
import json
import logging
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw

sys.path.insert(0, '.')

from attack_generator import AttackGenerator, AttackConfig
from detection import DetectionEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("NIDS-Test")

def normalize_scapy_packet(pkt):
    """Convert Scapy packet to normalized dict"""
    if IP not in pkt:
        return None
    
    ip = pkt[IP]
    result = {
        'src': ip.src,
        'dst': ip.dst,
        'protocol': 'OTHER',
        'src_port': 0,
        'dst_port': 0,
        'flags': '',
        'payload': b'',
        'timestamp': pkt.time if hasattr(pkt, 'time') else time.time(),
    }
    
    if TCP in pkt:
        tcp = pkt[TCP]
        result['protocol'] = 'TCP'
        result['src_port'] = tcp.sport
        result['dst_port'] = tcp.dport
        flags = []
        if tcp.flags & 0x02: flags.append('S')
        if tcp.flags & 0x10: flags.append('A')
        if tcp.flags & 0x04: flags.append('R')
        if tcp.flags & 0x08: flags.append('P')
        result['flags'] = ''.join(flags)
        
    elif UDP in pkt:
        udp = pkt[UDP]
        result['protocol'] = 'UDP'
        result['src_port'] = udp.sport
        result['dst_port'] = udp.dport
        
    elif ICMP in pkt:
        result['protocol'] = 'ICMP'
    
    if Raw in pkt:
        result['payload'] = bytes(pkt[Raw])
    
    return result

class TestFramework:
    def __init__(self):
        self.generator = AttackGenerator()
        # Create detector with NO cooldown for testing
        self.detector = DetectionEngine([])
        # Disable cooldown by setting it to 0
        self.detector.config.ALERT_COOLDOWN = 0
        # Set low confidence threshold for testing
        self.detector.set_confidence_threshold(30)
        logger.info(f"✓ Detector ready (cooldown: 0, threshold: 30%)")
    
    def test_attack(self, attack_type, **kwargs):
        """Test a single attack type"""
        logger.info(f"\n{'='*70}")
        logger.info(f"TEST: {attack_type.upper()}")
        logger.info(f"{'='*70}")
        
        config = AttackConfig(
            attack_type=attack_type,
            source_ip=kwargs.get('source', '192.168.1.100'),
            target_ip=kwargs.get('target', '10.0.0.1'),
            target_port=kwargs.get('port', 80),
            duration_seconds=kwargs.get('duration', 3),
            packet_rate=kwargs.get('rate', 100),
            num_sources=kwargs.get('sources', 1),
        )
        
        # Generate attack
        packets, pcap_file, expected_rule = self.generator.generate_and_log_attack(config, dry_run=True)
        logger.info(f"✓ Generated {len(packets)} packets")
        
        # Process ALL packets through detector
        logger.info(f"Processing {len(packets)} packets...")
        start_time = time.time()
        
        all_detections = []
        packet_count = 0
        
        for i, pkt in enumerate(packets):
            norm_pkt = normalize_scapy_packet(pkt)
            if norm_pkt:
                packet_count += 1
                alerts = self.detector.process_packet(norm_pkt)
                if alerts:
                    all_detections.extend(alerts)
        
        processing_time = time.time() - start_time
        
        # Calculate stats
        detection_rate = (len(all_detections) / packet_count * 100) if packet_count else 0
        
        # Get unique detection types
        detected_types = list(set(d['type'] for d in all_detections))
        
        logger.info(f"\nRESULTS:")
        logger.info(f"  Packets Processed: {packet_count}")
        logger.info(f"  Total Detections:  {len(all_detections)}")
        logger.info(f"  Detection Rate:    {detection_rate:.1f}%")
        logger.info(f"  Detected Types:    {', '.join(detected_types) if detected_types else 'None'}")
        logger.info(f"  Expected Rule:     {expected_rule}")
        logger.info(f"  Processing Time:   {processing_time*1000:.1f}ms")
        
        # Show sample detections
        if all_detections:
            logger.info(f"\nSample Detections (first 3):")
            for alert in all_detections[:3]:
                logger.info(f"  - {alert['type']} ({alert['confidence']:.0f}%)")
        
        # Determine pass/fail (expect 50%+ detection rate for payload attacks)
        pass_threshold = 50 if attack_type in ['sql_injection', 'xss', 'command_injection'] else 30
        status = "✓ PASS" if detection_rate >= pass_threshold else "✗ FAIL"
        logger.info(f"\nStatus: {status} (threshold: {pass_threshold}%)")
        
        return {
            'attack': attack_type,
            'packets': packet_count,
            'detections': len(all_detections),
            'rate': detection_rate,
            'detected_types': detected_types,
            'expected': expected_rule,
            'status': 'PASS' if detection_rate >= pass_threshold else 'FAIL'
        }

def main():
    """Run tests"""
    framework = TestFramework()
    
    # Test specific attacks
    tests = [
        ('sql_injection', {'duration': 2, 'rate': 20}),
        ('xss', {'duration': 2, 'rate': 20}),
        ('command_injection', {'duration': 2, 'rate': 20}),
        ('tcp_syn_flood', {'duration': 2, 'rate': 50}),
        ('udp_flood', {'duration': 2, 'rate': 50}),
        ('port_scan', {'duration': 1, 'rate': 20}),
    ]
    
    results = []
    for attack_type, kwargs in tests:
        result = framework.test_attack(attack_type, **kwargs)
        results.append(result)
        time.sleep(1)
    
    # Summary
    print("\n" + "="*70)
    print("FINAL TEST SUMMARY")
    print("="*70)
    print(f"{'Attack Type':<20} {'Packets':<10} {'Detections':<12} {'Rate':<10} {'Status':<10}")
    print("-"*70)
    
    passed = 0
    for r in results:
        status_icon = "✓" if r['status'] == 'PASS' else "✗"
        print(f"{r['attack']:<20} {r['packets']:<10} {r['detections']:<12} {r['rate']:.1f}%{'':<5} {status_icon} {r['status']}")
        if r['status'] == 'PASS':
            passed += 1
    
    print("-"*70)
    print(f"PASSED: {passed}/{len(results)} tests")
    print("="*70)

if __name__ == "__main__":
    main()

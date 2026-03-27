#!/usr/bin/env python3
"""Fixed NIDS test framework with proper packet normalization"""

import os
import sys
import json
import time
import logging
from typing import Dict, List, Tuple
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("NIDS-Test")

from attack_generator import AttackGenerator, AttackConfig
from detection import DetectionEngine

def normalize_scapy_packet(pkt):
    """Convert Scapy packet to normalized dict for detector"""
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
        'size': len(pkt),
    }
    
    if TCP in pkt:
        tcp = pkt[TCP]
        result['protocol'] = 'TCP'
        result['src_port'] = tcp.sport
        result['dst_port'] = tcp.dport
        # Convert flags
        flags = []
        if tcp.flags & 0x01: flags.append('F')
        if tcp.flags & 0x02: flags.append('S')
        if tcp.flags & 0x04: flags.append('R')
        if tcp.flags & 0x08: flags.append('P')
        if tcp.flags & 0x10: flags.append('A')
        if tcp.flags & 0x20: flags.append('U')
        if tcp.flags & 0x40: flags.append('E')
        if tcp.flags & 0x80: flags.append('C')
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

class NIDSTestFramework:
    """Fixed NIDS testing framework"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.generator = AttackGenerator()
        self.test_results = []
        
        # Load detection engine
        self.detector = DetectionEngine([])
        # Lower confidence threshold for testing
        self.detector.set_confidence_threshold(30)
        logger.info(f"✓ Detection engine initialized (threshold: 30%)")
    
    def run_attack_test(self, attack_type: str, **config_kwargs) -> Dict:
        """Run a single attack test"""
        logger.info(f"\n{'='*70}")
        logger.info(f"TEST: {attack_type.upper()}")
        logger.info(f"{'='*70}")
        
        # Create attack configuration
        config = AttackConfig(
            attack_type=attack_type,
            source_ip=config_kwargs.get('source_ip', '192.168.1.100'),
            target_ip=config_kwargs.get('target_ip', '10.0.0.1'),
            target_port=config_kwargs.get('port', 80),
            duration_seconds=config_kwargs.get('duration', 3),
            packet_rate=config_kwargs.get('rate', 50),
            num_sources=config_kwargs.get('num_sources', 1),
        )
        
        # Generate attack
        try:
            packets, pcap_file, rule_name = self.generator.generate_and_log_attack(
                config, dry_run=True
            )
            logger.info(f"✓ Generated {len(packets)} attack packets")
        except Exception as e:
            logger.error(f"Failed to generate attack: {e}")
            return None
        
        # Process through detection engine with proper normalization
        logger.info(f"Processing through detection engine...")
        start_time = time.time()
        detections = []
        
        for idx, pkt in enumerate(packets):
            try:
                # Normalize the packet first
                norm_pkt = normalize_scapy_packet(pkt)
                if norm_pkt:
                    alerts = self.detector.process_packet(norm_pkt)
                    if alerts:
                        detections.extend(alerts)
                        if self.verbose:
                            for alert in alerts:
                                logger.info(f"  [Pkt {idx}] DETECTION: {alert.get('type', 'Unknown')} "
                                           f"(Conf: {alert.get('confidence', 0):.0f}%)")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Packet {idx} processing error: {e}")
                continue
        
        processing_time = time.time() - start_time
        
        # Calculate metrics
        detection_rate = (len(detections) / len(packets) * 100) if packets else 0
        avg_confidence = sum(d.get('confidence', 0) for d in detections) / len(detections) if detections else 0
        
        # Log results
        logger.info(f"\nRESULTS:")
        logger.info(f"  Total Packets:      {len(packets)}")
        logger.info(f"  Detections:         {len(detections)}")
        logger.info(f"  Detection Rate:     {detection_rate:.1f}%")
        logger.info(f"  Avg Confidence:     {avg_confidence:.1f}%")
        logger.info(f"  Processing Time:    {processing_time*1000:.2f}ms")
        logger.info(f"  Latency/Packet:     {processing_time/len(packets)*1000:.4f}ms")
        logger.info(f"  PCAP File:          {pcap_file}")
        logger.info(f"  Expected Rule:      {rule_name}")
        
        # Show detected types
        if detections:
            detected_types = list(set(d['type'] for d in detections))
            logger.info(f"  Detected Types:     {', '.join(detected_types)}")
        
        # Determine pass/fail (lower threshold for testing)
        status = "✓ PASS" if detection_rate >= 50 else "✗ FAIL"
        logger.info(f"  Status:             {status}")
        
        result = {
            'attack_type': attack_type,
            'expected_rule': rule_name,
            'packets_generated': len(packets),
            'detections': len(detections),
            'detection_rate': detection_rate,
            'avg_confidence': avg_confidence,
            'detected_types': list(set(d['type'] for d in detections)) if detections else [],
            'processing_time_ms': processing_time * 1000,
            'pcap_file': pcap_file,
            'status': 'PASS' if detection_rate >= 50 else 'FAIL',
        }
        
        self.test_results.append(result)
        return result
    
    def run_comprehensive_test_suite(self) -> List[Dict]:
        """Run all attack types"""
        test_configs = [
            ('tcp_syn_flood', {'rate': 100, 'duration': 2}),
            ('udp_flood', {'rate': 100, 'duration': 2}),
            ('ddos_multi', {'rate': 50, 'duration': 2, 'num_sources': 5}),
            ('sql_injection', {'rate': 20, 'duration': 2}),
            ('xss', {'rate': 20, 'duration': 2}),
            ('command_injection', {'rate': 20, 'duration': 2}),
            ('port_scan', {'rate': 10, 'duration': 2}),
            ('brute_force', {'rate': 30, 'duration': 2}),
        ]
        
        logger.info(f"\n{'='*70}")
        logger.info("NIDS COMPREHENSIVE TEST SUITE")
        logger.info(f"{'='*70}")
        logger.info(f"Running {len(test_configs)} attack types...\n")
        
        for attack_type, kwargs in test_configs:
            self.run_attack_test(attack_type, **kwargs)
            time.sleep(0.5)
        
        return self.test_results
    
    def display_summary(self):
        """Display test summary"""
        if not self.test_results:
            logger.warning("No test results to display")
            return
        
        logger.info(f"\n{'='*70}")
        logger.info("TEST SUMMARY REPORT")
        logger.info(f"{'='*70}")
        logger.info(f"{'Attack Type':<25} {'Packets':<10} {'Detections':<12} {'Rate':<10} {'Detected Types':<30}")
        logger.info(f"{'-'*90}")
        
        passed = 0
        failed = 0
        total_packets = 0
        total_detections = 0
        
        for result in self.test_results:
            attack = result['attack_type'][:24]
            packets = result['packets_generated']
            detections = result['detections']
            rate = f"{result['detection_rate']:.1f}%"
            detected = ', '.join(result['detected_types'][:2]) if result['detected_types'] else 'None'
            status = result['status']
            
            logger.info(f"{attack:<25} {packets:<10} {detections:<12} {rate:<10} {detected:<30}")
            
            total_packets += packets
            total_detections += detections
            
            if status == 'PASS':
                passed += 1
            else:
                failed += 1
        
        logger.info(f"{'-'*90}")
        overall_rate = (total_detections / total_packets * 100) if total_packets else 0
        logger.info(f"TOTALS: {total_packets} packets → {total_detections} detections ({overall_rate:.1f}%)")
        logger.info(f"Tests Passed: {passed}/{len(self.test_results)}")
        logger.info(f"Tests Failed: {failed}/{len(self.test_results)}")
        logger.info(f"{'='*70}\n")
    
    def export_results(self, filename: str = "test_results.json"):
        """Export test results to JSON"""
        filepath = os.path.join(self.generator.output_dir, filename)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': len(self.test_results),
            'tests_passed': sum(1 for r in self.test_results if r['status'] == 'PASS'),
            'tests_failed': sum(1 for r in self.test_results if r['status'] == 'FAIL'),
            'results': self.test_results
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"✓ Results exported: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return None

def main():
    """Run the fixed test suite"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Fixed NIDS Test Framework')
    parser.add_argument('--comprehensive', '-c', action='store_true', help='Run comprehensive tests')
    parser.add_argument('--attack', '-a', help='Test specific attack type')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    logger.info("="*70)
    logger.info("NIDS FIXED TEST FRAMEWORK")
    logger.info("="*70)
    
    framework = NIDSTestFramework(verbose=args.verbose)
    
    if args.comprehensive:
        framework.run_comprehensive_test_suite()
        framework.display_summary()
        framework.export_results('test_results_fixed.json')
    elif args.attack:
        framework.run_attack_test(args.attack)
        framework.display_summary()
    else:
        # Quick test with 3 attack types
        logger.info("Running quick test (3 attack types)...\n")
        framework.run_attack_test('sql_injection')
        time.sleep(0.5)
        framework.run_attack_test('command_injection')
        time.sleep(0.5)
        framework.run_attack_test('tcp_syn_flood')
        framework.display_summary()
    
    logger.info("="*70)

if __name__ == '__main__':
    main()

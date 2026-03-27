#!/usr/bin/env python3
"""
INTEGRATED ATTACK GENERATION & DETECTION DEMO
==============================================

Demonstrates the complete workflow:
1. Generate synthetic attacks using attack_generator.py
2. Process through NIDS detection engine
3. Display real-time detections with confidence scores
4. Log evidence (PCAP + JSON)

Usage:
    python test_nids_integration.py
    python test_nids_integration.py --verbose
    python test_nids_integration.py --attack tcp_syn_flood
"""

import os
import sys
import json
import time
import logging
from typing import Dict, List, Tuple
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("NIDS-Test")

try:
    from scapy.all import rdpcap
    from attack_generator import AttackGenerator, AttackConfig
    from detection import DetectionEngine
except ImportError as e:
    logger.error(f"Import error: {e}")
    logger.error("Install dependencies: pip install scapy")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATED TESTING FRAMEWORK
# ─────────────────────────────────────────────────────────────────────────────

class NIDSTestFramework:
    """End-to-end NIDS testing framework"""
    
    def __init__(self, rules_file: str = "rules_tuned.json", verbose: bool = False):
        """Initialize test framework"""
        self.verbose = verbose
        self.generator = AttackGenerator()
        
        # Load detection engine
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
            self.detector = DetectionEngine(rules)
            logger.info(f"✓ Detection engine loaded ({len(rules)} rules)")
        except Exception as e:
            logger.error(f"Failed to load detection engine: {e}")
            sys.exit(1)
        
        self.test_results = []
    
    def run_attack_test(self, attack_type: str, **config_kwargs) -> Dict:
        """
        Run a single attack test
        
        Returns:
            Test result dictionary with detection stats
        """
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
                config, 
                dry_run=True  # Don't send packets
            )
            logger.info(f"✓ Generated {len(packets)} attack packets")
        except Exception as e:
            logger.error(f"Failed to generate attack: {e}")
            return None
        
        # Process through detection engine
        logger.info(f"Processing through detection engine...")
        start_time = time.time()
        detections = []
        false_positives = 0
        
        for idx, pkt in enumerate(packets):
            try:
                result = self.detector.process_packet(pkt)
                if result:
                    detections.append(result)
                    if self.verbose:
                        logger.info(f"  [Pkt {idx}] DETECTION: {result.get('rule_name', 'Unknown')} "
                                   f"(Conf: {result.get('confidence', 0):.0f}%)")
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Packet {idx} processing error: {e}")
                false_positives += 1
                continue
        
        processing_time = time.time() - start_time
        
        # Calculate metrics
        detection_rate = (len(detections) / len(packets) * 100) if packets else 0
        false_positive_rate = (false_positives / len(packets) * 100) if packets else 0
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
        
        # Determine pass/fail
        status = "✓ PASS" if detection_rate >= 80 else "✗ FAIL"
        logger.info(f"  Status:             {status}")
        
        # Store results
        result = {
            'attack_type': attack_type,
            'expected_rule': rule_name,
            'packets_generated': len(packets),
            'detections': len(detections),
            'detection_rate': detection_rate,
            'avg_confidence': avg_confidence,
            'processing_time_ms': processing_time * 1000,
            'latency_per_packet_ms': processing_time / len(packets) * 1000 if packets else 0,
            'pcap_file': pcap_file,
            'status': 'PASS' if detection_rate >= 80 else 'FAIL',
        }
        
        self.test_results.append(result)
        return result
    
    def run_comprehensive_test_suite(self) -> List[Dict]:
        """Run all attack types for comprehensive testing"""
        
        test_configs = [
            ('tcp_syn_flood', {'rate': 50, 'duration': 3}),
            ('tcp_ack_flood', {'rate': 50, 'duration': 3}),
            ('udp_flood', {'rate': 100, 'duration': 3}),
            ('icmp_flood', {'rate': 50, 'duration': 3}),
            ('ddos_multi', {'rate': 50, 'duration': 3, 'num_sources': 5}),
            ('sql_injection', {'rate': 20, 'duration': 3}),
            ('xss', {'rate': 20, 'duration': 3}),
            ('command_injection', {'rate': 20, 'duration': 3}),
            ('port_scan', {'rate': 10, 'duration': 3}),
            ('brute_force', {'rate': 30, 'duration': 3}),
        ]
        
        logger.info(f"\n{'='*70}")
        logger.info("NIDS COMPREHENSIVE TEST SUITE")
        logger.info(f"{'='*70}")
        logger.info(f"Running {len(test_configs)} attack types...\n")
        
        for attack_type, kwargs in test_configs:
            self.run_attack_test(attack_type, **kwargs)
            time.sleep(0.5)  # Brief pause between tests
        
        return self.test_results
    
    def display_summary(self):
        """Display test summary"""
        if not self.test_results:
            logger.warning("No test results to display")
            return
        
        logger.info(f"\n{'='*70}")
        logger.info("TEST SUMMARY REPORT")
        logger.info(f"{'='*70}")
        logger.info(f"{'Attack Type':<25} {'Packets':<10} {'Detections':<12} {'Rate':<10} {'Status':<10}")
        logger.info(f"{'-'*70}")
        
        passed = 0
        failed = 0
        total_packets = 0
        total_detections = 0
        
        for result in self.test_results:
            attack = result['attack_type'][:24]
            packets = result['packets_generated']
            detections = result['detections']
            rate = f"{result['detection_rate']:.1f}%"
            status = result['status']
            
            logger.info(f"{attack:<25} {packets:<10} {detections:<12} {rate:<10} {status:<10}")
            
            total_packets += packets
            total_detections += detections
            
            if status == 'PASS':
                passed += 1
            else:
                failed += 1
        
        logger.info(f"{'-'*70}")
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


# ─────────────────────────────────────────────────────────────────────────────
# QUICK ATTACK DEMO
# ─────────────────────────────────────────────────────────────────────────────

def demo_single_attack(attack_type: str = 'tcp_syn_flood', verbose: bool = False):
    """Run a single attack demo"""
    framework = NIDSTestFramework(verbose=verbose)
    framework.run_attack_test(attack_type)
    framework.export_results(f'test_results_{attack_type}.json')


def demo_comprehensive():
    """Run comprehensive test suite"""
    framework = NIDSTestFramework(verbose=False)
    framework.run_comprehensive_test_suite()
    framework.display_summary()
    framework.export_results('test_results_comprehensive.json')


# ─────────────────────────────────────────────────────────────────────────────
# CLI & MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='NIDS Integration Test Framework'
    )
    
    parser.add_argument(
        '--attack', '-a',
        default=None,
        choices=['tcp_syn_flood', 'tcp_ack_flood', 'udp_flood', 'icmp_flood',
                 'ddos_multi', 'sql_injection', 'xss', 'command_injection',
                 'port_scan', 'brute_force'],
        help='Run single attack test'
    )
    
    parser.add_argument(
        '--comprehensive', '-c',
        action='store_true',
        help='Run comprehensive test suite (all attacks)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='test_results.json',
        help='Output file for results'
    )
    
    args = parser.parse_args()
    
    logger.info("="*70)
    logger.info("NIDS DETECTION ENGINE TEST FRAMEWORK")
    logger.info("="*70)
    logger.info(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)
    
    if args.comprehensive:
        demo_comprehensive()
    elif args.attack:
        demo_single_attack(args.attack, verbose=args.verbose)
    else:
        # Default: Run quick 3-attack demo
        logger.info("Running demo (3 attack types)...\n")
        framework = NIDSTestFramework(verbose=args.verbose)
        
        for attack in ['tcp_syn_flood', 'sql_injection', 'ddos_multi']:
            framework.run_attack_test(attack, duration=2, rate=30)
            time.sleep(0.5)
        
        framework.display_summary()
        framework.export_results(args.output)
    
    logger.info(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)


if __name__ == '__main__':
    main()

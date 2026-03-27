#!/usr/bin/env python3
"""Headless PCAP analyzer - no GUI required"""

import sys
import time
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from detection import DetectionEngine

def normalize_packet(pkt):
    """Normalize Scapy packet for detection engine"""
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
        # Convert flags
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

def analyze_pcap(pcap_file, max_packets=100):
    """Analyze a PCAP file and print detections"""
    print(f"\n{'='*80}")
    print(f"Analyzing: {pcap_file}")
    print(f"{'='*80}")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"Total packets: {len(packets)}")
        print(f"Analyzing first {min(max_packets, len(packets))} packets...\n")
        
        detector = DetectionEngine([])
        detector.set_confidence_threshold(30)  # Lower threshold for testing
        
        alerts = []
        attack_types = set()
        
        for i, pkt in enumerate(packets[:max_packets]):
            norm_pkt = normalize_packet(pkt)
            if norm_pkt:
                result = detector.process_packet(norm_pkt)
                if result:
                    alerts.extend(result)
                    for alert in result:
                        attack_types.add(alert['type'])
                        
                        # Print packet details
                        print(f"[Packet {i:3d}] {alert['type']:<35} "
                              f"Confidence: {alert['confidence']:5.1f}% | "
                              f"Severity: {alert['severity']:<8} | "
                              f"Source: {norm_pkt['src']}:{norm_pkt['src_port']} → "
                              f"Target: {norm_pkt['dst']}:{norm_pkt['dst_port']}")
        
        # Summary
        print(f"\n{'='*80}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*80}")
        print(f"Total packets analyzed: {min(max_packets, len(packets))}")
        print(f"Total detections: {len(alerts)}")
        print(f"Unique attack types: {len(attack_types)}")
        
        if attack_types:
            print(f"\nDetected attacks:")
            for attack in sorted(attack_types):
                count = sum(1 for a in alerts if a['type'] == attack)
                avg_conf = sum(a['confidence'] for a in alerts if a['type'] == attack) / count
                print(f"  - {attack:<35} {count:>3} detections (avg confidence: {avg_conf:.1f}%)")
        
        # Per-packet detection rate
        detection_rate = (len(alerts) / min(max_packets, len(packets)) * 100) if packets else 0
        print(f"\nDetection rate: {detection_rate:.1f}%")
        
        return alerts
        
    except Exception as e:
        print(f"Error analyzing {pcap_file}: {e}")
        return []

if __name__ == "__main__":
    import sys
    import glob
    
    if len(sys.argv) > 1:
        # Analyze specific PCAP files
        for pcap in sys.argv[1:]:
            analyze_pcap(pcap)
    else:
        # Analyze the 3 most recent PCAP files
        pcap_files = sorted(glob.glob("attacks/*.pcap"))[-3:]
        print(f"Analyzing {len(pcap_files)} most recent PCAP files...")
        for pcap in pcap_files:
            analyze_pcap(pcap)
            print()

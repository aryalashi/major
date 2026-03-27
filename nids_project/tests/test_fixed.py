#!/usr/bin/env python3
"""Fixed NIDS testing script"""

import sys
import json
import time
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw

sys.path.insert(0, '.')

from detection import DetectionEngine

def normalize_scapy_packet(pkt):
    """Convert Scapy packet to normalized dict for detector"""
    if IP not in pkt:
        return None
    
    ip_layer = pkt[IP]
    result = {
        'src': ip_layer.src,
        'dst': ip_layer.dst,
        'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'ICMP' if ICMP in pkt else 'OTHER',
        'src_port': 0,
        'dst_port': 0,
        'flags': '',
        'payload': b'',
        'timestamp': time.time(),
    }
    
    if TCP in pkt:
        tcp = pkt[TCP]
        result['src_port'] = tcp.sport
        result['dst_port'] = tcp.dport
        result['flags'] = tcp.sprintf('%flags%')
        if Raw in pkt:
            result['payload'] = bytes(pkt[Raw])
    
    elif UDP in pkt:
        udp = pkt[UDP]
        result['src_port'] = udp.sport
        result['dst_port'] = udp.dport
        if Raw in pkt:
            result['payload'] = bytes(pkt[Raw])
    
    elif ICMP in pkt:
        result['protocol'] = 'ICMP'
        if Raw in pkt:
            result['payload'] = bytes(pkt[Raw])
    
    return result

def test_pcap(pcap_file, expected_attack):
    """Test a PCAP file against detection engine"""
    print(f"\n{'='*60}")
    print(f"Testing: {pcap_file}")
    print(f"Expected: {expected_attack}")
    print(f"{'='*60}")
    
    detector = DetectionEngine([])
    
    try:
        packets = rdpcap(pcap_file)
        print(f"[*] Loaded {len(packets)} packets")
        
        detections = []
        for i, pkt in enumerate(packets[:100]):  # Limit to 100 packets
            norm_pkt = normalize_scapy_packet(pkt)
            if norm_pkt:
                alerts = detector.process_packet(norm_pkt)
                if alerts:
                    detections.extend(alerts)
                    for alert in alerts:
                        print(f"  [Pkt {i}] {alert['type']} - {alert['confidence']:.1f}%")
        
        print(f"\n[*] Results:")
        print(f"  Total detections: {len(detections)}")
        if detections:
            print(f"  Detected types: {set(a['type'] for a in detections)}")
        
        return len(detections) > 0
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

# Test the most recent PCAP files
import glob
import os

pcap_files = sorted(glob.glob("attacks/*.pcap"))[-3:]  # Last 3 files

if pcap_files:
    for pcap in pcap_files:
        attack_type = os.path.basename(pcap).split('_')[-1].replace('.pcap', '')
        test_pcap(pcap, attack_type)
else:
    print("[!] No PCAP files found. Generate some first:")
    print("    python attack_generator.py --attack tcp_syn_flood")

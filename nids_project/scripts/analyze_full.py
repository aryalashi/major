#!/usr/bin/env python3
"""Full PCAP analysis without cooldown limits"""

import sys
import time
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from detection import DetectionEngine

class FullAnalyzer:
    def __init__(self):
        self.detector = DetectionEngine([])
        self.detector.set_confidence_threshold(30)
        # Disable cooldown for full analysis
        self.detector.config.ALERT_COOLDOWN = 0
        print("[*] Detector initialized (cooldown disabled for analysis)")
    
    def normalize_packet(self, pkt):
        """Normalize Scapy packet"""
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
    
    def analyze(self, pcap_file, max_packets=100):
        """Analyze PCAP file with full detection"""
        print(f"\n{'='*80}")
        print(f"Analyzing: {pcap_file}")
        print(f"{'='*80}")
        
        packets = rdpcap(pcap_file)
        print(f"Total packets: {len(packets)}")
        print(f"Analyzing first {min(max_packets, len(packets))} packets...\n")
        
        alerts_by_type = {}
        total_alerts = 0
        
        for i, pkt in enumerate(packets[:max_packets]):
            norm_pkt = self.normalize_packet(pkt)
            if norm_pkt:
                alerts = self.detector.process_packet(norm_pkt)
                if alerts:
                    total_alerts += len(alerts)
                    for alert in alerts:
                        alert_type = alert['type']
                        if alert_type not in alerts_by_type:
                            alerts_by_type[alert_type] = []
                        alerts_by_type[alert_type].append({
                            'packet': i,
                            'confidence': alert['confidence'],
                            'src': norm_pkt['src'],
                            'dst': norm_pkt['dst']
                        })
                        
                        # Print first 10 detections
                        if len(alerts_by_type[alert_type]) <= 10:
                            print(f"[Packet {i:3d}] {alert_type:<35} "
                                  f"Confidence: {alert['confidence']:5.1f}% | "
                                  f"Severity: {alert['severity']:<8} | "
                                  f"{norm_pkt['src']}:{norm_pkt['src_port']} → "
                                  f"{norm_pkt['dst']}:{norm_pkt['dst_port']}")
        
        # Summary
        print(f"\n{'='*80}")
        print("FULL ANALYSIS SUMMARY")
        print(f"{'='*80}")
        print(f"Packets analyzed: {min(max_packets, len(packets))}")
        print(f"Total detections: {total_alerts}")
        print(f"Unique attack types: {len(alerts_by_type)}")
        
        if alerts_by_type:
            print(f"\nDetailed breakdown:")
            for attack_type, alerts in sorted(alerts_by_type.items()):
                confidences = [a['confidence'] for a in alerts]
                avg_conf = sum(confidences) / len(confidences)
                print(f"\n  {attack_type}:")
                print(f"    Total: {len(alerts)} detections")
                print(f"    Avg Confidence: {avg_conf:.1f}%")
                print(f"    Detection rate: {(len(alerts) / min(max_packets, len(packets))) * 100:.1f}%")
                print(f"    First detection at packet {alerts[0]['packet']}")
        
        detection_rate = (total_alerts / min(max_packets, len(packets))) * 100
        print(f"\nOverall detection rate: {detection_rate:.1f}%")
        
        return alerts_by_type

if __name__ == "__main__":
    import sys
    import glob
    
    analyzer = FullAnalyzer()
    
    if len(sys.argv) > 1:
        for pcap in sys.argv[1:]:
            analyzer.analyze(pcap)
    else:
        # Analyze recent attacks
        recent_pcaps = sorted(glob.glob("attacks/*.pcap"))[-5:]
        print(f"Analyzing {len(recent_pcaps)} most recent PCAP files...")
        for pcap in recent_pcaps:
            analyzer.analyze(pcap, max_packets=50)
            print()

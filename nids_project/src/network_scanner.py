#!/usr/bin/env python3
"""
NETWORK SCANNER - LAN Network Analysis & Threat Detection
===================================================

Scans the connected LAN network for:
- Connected devices/hosts
- Network-level packet anomalies
- DDoS attacks targeting network
- Port scanning activities
- Brute force attempts
- Malicious traffic patterns

Integrates with AdvancedSignatureDetector for real-time threat analysis.

Author: Advanced NIDS Team
Date: March 27, 2026
"""

import socket
import struct
import textwrap
import threading
import time
import json
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from detection import DetectionEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("NetworkScanner")


class NetworkDevice:
    """Represents a connected device on the network"""
    
    def __init__(self, ip: str, mac: str = None):
        self.ip = ip
        self.mac = mac
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.alerts = []
        self.threat_level = 0  # 0-100 confidence score
        self.is_malicious = False
    
    def update_activity(self, direction: str, packet_size: int):
        """Update device activity statistics"""
        self.last_seen = datetime.now()
        
        if direction == 'sent':
            self.packets_sent += 1
            self.bytes_sent += packet_size
        elif direction == 'received':
            self.packets_received += 1
            self.bytes_received += packet_size
    
    def add_alert(self, alert: Dict):
        """Add detected alert for this device"""
        self.alerts.append(alert)
        # Update threat level based on confidence
        self.threat_level = max(self.threat_level, alert.get('confidence', 0))
        
        if alert.get('confidence', 0) >= 75:
            self.is_malicious = True
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'threat_level': self.threat_level,
            'is_malicious': self.is_malicious,
            'alerts_count': len(self.alerts),
        }


class NetworkScanner:
    """
    Scans LAN network for threats using advanced detection engine.
    
    Features:
    - Device discovery and tracking
    - Real-time packet analysis
    - Attack detection per device
    - Network-level anomaly detection
    - Threat statistics and reports
    """
    
    def __init__(self, local_ip: str = None):
        """Initialize network scanner"""
        self.local_ip = local_ip or self._get_local_ip()
        self.local_network = self._get_network_prefix(self.local_ip)
        
        # Device tracking
        self.devices: Dict[str, NetworkDevice] = {}
        self.device_lock = threading.Lock()
        
        # Detection engine
        self.detector = DetectionEngine([])
        self.detector.set_confidence_threshold(50)
        
        # Statistics
        self.total_packets = 0
        self.total_alerts = 0
        self.threats_detected = []
        self.scanning = False
        
        logger.info(f"[NETWORK SCANNER] Initialized for network: {self.local_network}")
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_network_prefix(self, ip: str) -> str:
        """Get network prefix (e.g., 192.168.1.0/24)"""
        parts = ip.split('.')
        return f"{'.'.join(parts[:3])}.0/24"
    
    def discover_devices(self, subnet: str = None) -> List[str]:
        """
        Discover active devices on the network using ARP.
        
        Args:
            subnet: Network subnet (default: detected local network)
        
        Returns:
            List of discovered device IPs
        """
        if subnet is None:
            subnet = self.local_network.split('/')[0].rsplit('.', 1)[0]  # e.g., 192.168.1
        
        logger.info(f"[DISCOVERY] Scanning network: {subnet}.0/24")
        discovered = []
        
        # Windows ARP scan
        try:
            for i in range(1, 255):
                target_ip = f"{subnet}.{i}"
                if target_ip.split('.')[-1] != '0' and target_ip.split('.')[-1] != '255':
                    try:
                        response = socket.gethostbyaddr(target_ip)
                        discovered.append(target_ip)
                        logger.info(f"  [✓] Found: {target_ip} ({response[0]})")
                    except:
                        pass
        except Exception as e:
            logger.warning(f"[DISCOVERY] Error during scan: {e}")
        
        logger.info(f"[DISCOVERY] Found {len(discovered)} active device(s)")
        return discovered
    
    def add_device(self, ip: str, mac: str = None) -> NetworkDevice:
        """Add device to tracking"""
        with self.device_lock:
            if ip not in self.devices:
                device = NetworkDevice(ip, mac)
                self.devices[ip] = device
                logger.info(f"[DEVICE] Added: {ip}")
            return self.devices[ip]
    
    def process_lan_packet(self, packet_bytes: bytes, src_ip: str, dst_ip: str, 
                          protocol: str = 'TCP', src_port: int = 0, dst_port: int = 0):
        """
        Process packet from LAN and check for threats.
        
        Args:
            packet_bytes: Raw packet bytes
            src_ip: Source IP
            dst_ip: Destination IP
            protocol: Transport protocol
            src_port: Source port
            dst_port: Destination port
        """
        self.total_packets += 1
        
        # Add devices if new
        src_device = self.add_device(src_ip)
        dst_device = self.add_device(dst_ip)
        
        # Update activity
        src_device.update_activity('sent', len(packet_bytes))
        dst_device.update_activity('received', len(packet_bytes))
        
        # Build normalized packet for detection
        packet = {
            'src': src_ip,
            'dst': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'flags': '',
            'payload': packet_bytes,
            'timestamp': time.time(),
        }
        
        # Run detection
        try:
            alerts = self.detector.process_packet(packet)
            
            if alerts:
                self.total_alerts += len(alerts)
                
                for alert in alerts:
                    # Add to device alerts
                    src_device.add_alert(alert)
                    dst_device.add_alert(alert)
                    
                    # Log threat
                    self.threats_detected.append({
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': src_ip,
                        'dest_ip': dst_ip,
                        'alert_type': alert.get('type'),
                        'severity': alert.get('severity'),
                        'confidence': alert.get('confidence'),
                    })
                    
                    logger.warning(
                        f"[THREAT DETECTED] {alert['type']} | "
                        f"From: {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                        f"Confidence: {alert.get('confidence', 0):.1f}% | "
                        f"Severity: {alert.get('severity')}"
                    )
        except Exception as e:
            logger.error(f"[ERROR] Detection failed: {e}")
    
    def start_monitoring(self, interface: str = None, duration: int = None):
        """
        Start monitoring network in real-time.
        
        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds (None = indefinite)
        """
        self.scanning = True
        logger.info(f"[MONITOR] Starting network monitoring (interface: {interface})")
        
        try:
            start_time = time.time()
            
            while self.scanning:
                if duration and (time.time() - start_time) > duration:
                    break
                
                # Capture packets (implementation depends on platform)
                # This is a placeholder - actual implementation uses scapy or similar
                # For now, we'll demonstrate the structure
                
                time.sleep(0.1)  # Brief sleep to prevent CPU spinning
        
        except KeyboardInterrupt:
            logger.info("[MONITOR] Monitoring stopped by user")
        except Exception as e:
            logger.error(f"[MONITOR] Error during monitoring: {e}")
        finally:
            self.scanning = False
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.scanning = False
        logger.info("[MONITOR] Stopping network scan")
    
    def get_device_stats(self, ip: str = None) -> Dict:
        """Get statistics for a device or all devices"""
        with self.device_lock:
            if ip:
                if ip in self.devices:
                    return self.devices[ip].to_dict()
                return None
            
            return {
                ip: device.to_dict()
                for ip, device in self.devices.items()
            }
    
    def get_malicious_devices(self) -> List[Dict]:
        """Get list of detected malicious devices"""
        with self.device_lock:
            malicious = []
            for ip, device in self.devices.items():
                if device.is_malicious:
                    malicious.append({
                        'ip': ip,
                        'threat_level': device.threat_level,
                        'alerts': len(device.alerts),
                        'latest_alert': device.alerts[-1] if device.alerts else None,
                    })
            
            return sorted(malicious, key=lambda x: x['threat_level'], reverse=True)
    
    def get_network_stats(self) -> Dict:
        """Get overall network statistics"""
        with self.device_lock:
            malicious_count = sum(1 for d in self.devices.values() if d.is_malicious)
            
            return {
                'local_network': self.local_network,
                'local_ip': self.local_ip,
                'total_devices': len(self.devices),
                'malicious_devices': malicious_count,
                'total_packets_processed': self.total_packets,
                'total_alerts': self.total_alerts,
                'threats_detected': self.threats_detected[-10:],  # Last 10 threats
                'devices': self.get_device_stats(),
            }
    
    def generate_report(self) -> str:
        """Generate text report of network scan"""
        stats = self.get_network_stats()
        malicious = self.get_malicious_devices()
        
        report = f"""
╔════════════════════════════════════════════════════════════════╗
║              NETWORK SCAN REPORT
║              {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚════════════════════════════════════════════════════════════════╝

NETWORK INFORMATION
───────────────────
  Local Network:         {stats['local_network']}
  Local IP:              {stats['local_ip']}
  Total Devices Found:   {stats['total_devices']}
  
THREAT SUMMARY
──────────────
  Malicious Devices:     {stats['malicious_devices']}
  Total Packets:         {stats['total_packets_processed']}
  Total Alerts:          {stats['total_alerts']}
  Alert Rate:            {(stats['total_alerts']/max(1, stats['total_packets_processed'])*100):.2f}%

"""
        
        if malicious:
            report += "MALICIOUS DEVICES\n──────────────────\n"
            for device in malicious:
                report += f"  {device['ip']:<15} Threat: {device['threat_level']:>6.1f}% | Alerts: {device['alerts']:>3}\n"
        
        if stats['threats_detected']:
            report += "\nRECENT THREATS\n──────────────\n"
            for threat in stats['threats_detected'][-5:]:
                report += f"  [{threat['timestamp']}] {threat['alert_type']:<20} "
                report += f"{threat['source_ip']}:{threat['dest_ip']:<15} "
                report += f"Confidence: {threat['confidence']:.1f}%\n"
        
        return report
    
    def export_json(self, filepath: str = None) -> str:
        """Export scan results to JSON"""
        stats = self.get_network_stats()
        
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(stats, f, indent=2)
            logger.info(f"[EXPORT] Report saved to {filepath}")
            return filepath
        else:
            return json.dumps(stats, indent=2)


def demo():
    """Demo network scanner"""
    print("\n[*] Network Scanner Demo\n")
    
    scanner = NetworkScanner()
    
    print(f"[*] Local Network: {scanner.local_network}")
    print(f"[*] Local IP: {scanner.local_ip}\n")
    
    # Skip actual discovery (takes time), use simulated devices
    print("[*] Adding simulated devices...\n")
    devices = [
        ("192.168.1.50", "AA:BB:CC:DD:EE:01"),
        ("192.168.1.100", "AA:BB:CC:DD:EE:02"),
        ("192.168.1.101", "AA:BB:CC:DD:EE:03"),
    ]
    
    for ip, mac in devices:
        scanner.add_device(ip, mac)
    
    print(f"[*] Simulated {len(devices)} device(s)\n")
    print("[*] Processing test packets for threat detection...\n")
    
    # Simulate network traffic for demonstration
    test_packets = [
        # Normal traffic
        (b"GET / HTTP/1.1\r\nHost: example.com", "192.168.1.50", "192.168.1.1", "TCP", 54321, 80),
        
        # Malicious traffic
        (b"SELECT * FROM users WHERE id=1 OR 1=1--", "192.168.1.100", "192.168.1.200", "TCP", 54322, 3306),
        (b"<img src=x onerror=alert('XSS')>", "192.168.1.101", "192.168.1.1", "TCP", 54323, 80),
    ]
    
    for packet, src, dst, proto, sport, dport in test_packets:
        scanner.process_lan_packet(packet, src, dst, proto, sport, dport)
        time.sleep(0.1)
    
    # Print report
    print(scanner.generate_report())
    
    print("[*] Demo complete!")


if __name__ == "__main__":
    demo()

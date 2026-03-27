#!/usr/bin/env python3
"""
HOTSPOT MONITOR - Connected Hotspot Devices & Attack Tracking
============================================================

Monitors connected devices to a PC's hotspot/shared network and tracks:
- Connected devices (phones, tablets, laptops, etc.)
- Data usage per device
- Attacks originating from connected devices
- Attacks targeting connected devices
- Malicious activity detection
- Real-time threat alerts

Integrates with AdvancedSignatureDetector for threat detection.

Author: Advanced NIDS Team
Date: March 27, 2026
"""

import threading
import time
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from detection import DetectionEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("HotspotMonitor")


class HotspotClient:
    """Represents a device connected to the hotspot"""
    
    def __init__(self, mac: str, ip: str = None, hostname: str = None):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname or "Unknown Device"
        self.connected_at = datetime.now()
        self.disconnected_at = None
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.data_limit = None  # Bytes per session
        self.is_active = True
        self.attacks_from_device = []  # Attacks originating from this device
        self.attacks_to_device = []    # Attacks targeting this device
        self.threat_level = 0
        self.is_blocked = False
        self.connection_quality = 100  # 0-100 signal strength
    
    def add_attack_from_device(self, attack: Dict):
        """Record attack originating from this device"""
        self.attacks_from_device.append({
            'timestamp': datetime.now().isoformat(),
            'type': attack.get('type'),
            'target_ip': attack.get('dst'),
            'target_port': attack.get('dst_port'),
            'confidence': attack.get('confidence'),
            'severity': attack.get('severity'),
        })
        
        # Update threat level
        self.threat_level = max(self.threat_level, attack.get('confidence', 0))
        
        logger.warning(
            f"[ATTACK FROM DEVICE] {self.hostname} ({self.mac}) → "
            f"{attack.get('type')} | Confidence: {attack.get('confidence', 0):.1f}%"
        )
    
    def add_attack_to_device(self, attack: Dict):
        """Record attack targeting this device"""
        self.attacks_to_device.append({
            'timestamp': datetime.now().isoformat(),
            'type': attack.get('type'),
            'source_ip': attack.get('src'),
            'source_port': attack.get('src_port'),
            'confidence': attack.get('confidence'),
            'severity': attack.get('severity'),
        })
        
        logger.warning(
            f"[ATTACK TO DEVICE] {self.hostname} ({self.mac}) ← "
            f"{attack.get('type')} | Confidence: {attack.get('confidence', 0):.1f}%"
        )
    
    def update_activity(self, direction: str, packet_size: int):
        """Update device activity"""
        if direction == 'sent':
            self.packets_sent += 1
            self.bytes_sent += packet_size
        elif direction == 'received':
            self.packets_received += 1
            self.bytes_received += packet_size
    
    def get_session_duration(self) -> str:
        """Get connection duration"""
        end = self.disconnected_at or datetime.now()
        duration = end - self.connected_at
        
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    
    def get_data_usage(self) -> str:
        """Get formatted data usage"""
        total_bytes = self.bytes_sent + self.bytes_received
        
        if total_bytes > 1024*1024*1024:  # GiB
            return f"{total_bytes / (1024*1024*1024):.2f} GiB"
        elif total_bytes > 1024*1024:  # MiB
            return f"{total_bytes / (1024*1024):.2f} MiB"
        elif total_bytes > 1024:  # KiB
            return f"{total_bytes / 1024:.2f} KiB"
        else:
            return f"{total_bytes} B"
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'mac': self.mac,
            'ip': self.ip,
            'hostname': self.hostname,
            'connected_at': self.connected_at.isoformat(),
            'session_duration': self.get_session_duration(),
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'data_usage': self.get_data_usage(),
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'is_active': self.is_active,
            'threat_level': self.threat_level,
            'is_blocked': self.is_blocked,
            'attacks_from_device': len(self.attacks_from_device),
            'attacks_to_device': len(self.attacks_to_device),
            'total_attacks': len(self.attacks_from_device) + len(self.attacks_to_device),
            'connection_quality': self.connection_quality,
        }


class HotspotMonitor:
    """
    Monitor devices connected to PC hotspot and track attacks.
    
    Features:
    - Device connection tracking
    - Real-time attack detection
    - Per-device threat scoring
    - Data usage monitoring
    - Security alerts
    - Connection quality metrics
    """
    
    def __init__(self, hotspot_ip: str = "192.168.43.1"):
        """Initialize hotspot monitor"""
        self.hotspot_ip = hotspot_ip
        self.gateway_ip = hotspot_ip
        
        # Connected devices
        self.clients: Dict[str, HotspotClient] = {}
        self.clients_lock = threading.Lock()
        
        # Detection engine
        self.detector = DetectionEngine([])
        self.detector.set_confidence_threshold(50)
        
        # Statistics
        self.total_packets = 0
        self.total_alerts = 0
        self.monitoring = False
        self.blocked_clients = []
        
        logger.info(f"[HOTSPOT MONITOR] Initialized (Hotspot IP: {self.hotspot_ip})")
    
    def add_client(self, mac: str, ip: str = None, hostname: str = None) -> HotspotClient:
        """Add connected client"""
        with self.clients_lock:
            if mac not in self.clients:
                client = HotspotClient(mac, ip, hostname)
                self.clients[mac] = client
                logger.info(f"[CLIENT CONNECTED] {hostname or mac} | MAC: {mac} | IP: {ip}")
            else:
                # Reconnection
                self.clients[mac].is_active = True
                self.clients[mac].connected_at = datetime.now()
                logger.info(f"[CLIENT RECONNECTED] {hostname or mac}")
            
            return self.clients[mac]
    
    def remove_client(self, mac: str):
        """Client disconnected"""
        with self.clients_lock:
            if mac in self.clients:
                client = self.clients[mac]
                client.is_active = False
                client.disconnected_at = datetime.now()
                logger.info(f"[CLIENT DISCONNECTED] {client.hostname} | Duration: {client.get_session_duration()}")
    
    def process_client_packet(self, mac: str, hostname: str, src_ip: str, dst_ip: str,
                             protocol: str, src_port: int, dst_port: int, 
                             payload: bytes, direction: str = 'outgoing'):
        """
        Process packet from/to hotspot client.
        
        Args:
            mac: Client MAC address
            hostname: Client hostname/name
            src_ip: Source IP
            dst_ip: Destination IP
            protocol: Transport protocol
            src_port: Source port
            dst_port: Destination port
            payload: Packet payload
            direction: 'outgoing' (from device) or 'incoming' (to device)
        """
        self.total_packets += 1
        
        # Get or create client
        client = self.add_client(mac, src_ip if direction == 'outgoing' else dst_ip, hostname)
        
        # Update activity
        client.update_activity(direction, len(payload))
        
        # Build packet for detection
        packet = {
            'src': src_ip,
            'dst': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'flags': '',
            'payload': payload,
            'timestamp': time.time(),
        }
        
        # Run threat detection
        try:
            alerts = self.detector.process_packet(packet)
            
            if alerts:
                self.total_alerts += len(alerts)
                
                for alert in alerts:
                    if direction == 'outgoing':
                        # Attack originating from this device
                        client.add_attack_from_device(alert)
                    else:
                        # Attack targeting this device
                        client.add_attack_to_device(alert)
        
        except Exception as e:
            logger.error(f"[ERROR] Detection failed: {e}")
    
    def get_client(self, mac: str) -> Optional[HotspotClient]:
        """Get client by MAC address"""
        with self.clients_lock:
            return self.clients.get(mac)
    
    def get_all_clients(self) -> Dict[str, HotspotClient]:
        """Get all clients"""
        with self.clients_lock:
            return dict(self.clients)
    
    def get_active_clients(self) -> List[Dict]:
        """Get list of active clients"""
        with self.clients_lock:
            active = [
                client.to_dict()
                for client in self.clients.values()
                if client.is_active
            ]
            return sorted(active, key=lambda x: x['bytes_received'] + x['bytes_sent'], reverse=True)
    
    def get_suspicious_clients(self) -> List[Dict]:
        """Get clients with suspicious activity"""
        with self.clients_lock:
            suspicious = [
                client.to_dict()
                for client in self.clients.values()
                if client.threat_level > 0 or len(client.attacks_from_device) > 0
            ]
            return sorted(suspicious, key=lambda x: x['threat_level'], reverse=True)
    
    def block_client(self, mac: str, reason: str = "Malicious activity detected"):
        """Block client from hotspot"""
        with self.clients_lock:
            if mac in self.clients:
                self.clients[mac].is_blocked = True
                self.blocked_clients.append({
                    'mac': mac,
                    'hostname': self.clients[mac].hostname,
                    'reason': reason,
                    'blocked_at': datetime.now().isoformat(),
                })
                logger.warning(f"[BLOCKED] {self.clients[mac].hostname} ({mac}) - {reason}")
    
    def unblock_client(self, mac: str):
        """Unblock client"""
        with self.clients_lock:
            if mac in self.clients:
                self.clients[mac].is_blocked = False
                self.blocked_clients = [b for b in self.blocked_clients if b['mac'] != mac]
                logger.info(f"[UNBLOCKED] {self.clients[mac].hostname} ({mac})")
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        with self.clients_lock:
            active_clients = [c for c in self.clients.values() if c.is_active]
            suspicious_clients = [c for c in self.clients.values() if c.threat_level > 0]
            
            total_data = sum(c.bytes_sent + c.bytes_received for c in self.clients.values())
            
            attack_summary = defaultdict(int)
            for client in self.clients.values():
                for attack in client.attacks_from_device + client.attacks_to_device:
                    attack_summary[attack['type']] += 1
            
            return {
                'hotspot_ip': self.hotspot_ip,
                'timestamp': datetime.now().isoformat(),
                'total_clients': len(self.clients),
                'active_clients': len(active_clients),
                'suspicious_clients': len(suspicious_clients),
                'blocked_clients': len(self.blocked_clients),
                'total_packets': self.total_packets,
                'total_alerts': self.total_alerts,
                'total_data_transferred': total_data,
                'attack_summary': dict(attack_summary),
                'clients': {mac: client.to_dict() for mac, client in self.clients.items()},
            }
    
    def generate_report(self) -> str:
        """Generate text report"""
        stats = self.get_statistics()
        suspicious = self.get_suspicious_clients()
        
        report = f"""
╔════════════════════════════════════════════════════════════════╗
║          HOTSPOT MONITOR REPORT
║          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚════════════════════════════════════════════════════════════════╝

HOTSPOT INFORMATION
───────────────────
  Hotspot IP:            {stats['hotspot_ip']}
  Total Devices:         {stats['total_clients']}
  Active Devices:        {stats['active_clients']}
  
SECURITY SUMMARY
────────────────
  Suspicious Devices:    {stats['suspicious_clients']}
  Blocked Devices:       {stats['blocked_clients']}
  Total Packets:         {stats['total_packets']}
  Total Alerts:          {stats['total_alerts']}
  Alert Rate:            {(stats['total_alerts']/max(1, stats['total_packets'])*100):.2f}%

CONNECTED DEVICES
─────────────────
"""
        
        for client_data in self.get_active_clients():
            threat_indicator = "🚨" if client_data['threat_level'] > 0 else "✓"
            report += f"\n  {threat_indicator} {client_data['hostname']:<20} | MAC: {client_data['mac']}\n"
            report += f"     ├─ IP: {client_data['ip']}\n"
            report += f"     ├─ Connected: {client_data['session_duration']}\n"
            report += f"     ├─ Data: {client_data['data_usage']}\n"
            report += f"     ├─ Packets: {client_data['packets_sent']} ↑ / {client_data['packets_received']} ↓\n"
            report += f"     └─ Threat Level: {client_data['threat_level']:.1f}%\n"
        
        if suspicious:
            report += "\n\nSUSPICIOUS DEVICES\n──────────────────\n"
            for device in suspicious:
                report += f"  • {device['hostname']:<20} Threat: {device['threat_level']:>6.1f}% | "
                report += f"Attacks: {device['total_attacks']:>2}\n"
        
        if stats['blocked_clients'] > 0:
            report += f"\n\nBLOCKED DEVICES ({stats['blocked_clients']})\n"
            report += "──────────────────────────────────────────\n"
            for blocked in self.blocked_clients:
                report += f"  • {blocked['hostname']:<30} - {blocked['reason']}\n"
        
        if stats['attack_summary']:
            report += "\n\nATTACK SUMMARY\n──────────────\n"
            for attack_type, count in sorted(stats['attack_summary'].items(), 
                                           key=lambda x: x[1], reverse=True):
                report += f"  {attack_type:<30} {count:>3} alert(s)\n"
        
        return report
    
    def export_json(self, filepath: str = None) -> str:
        """Export to JSON"""
        stats = self.get_statistics()
        
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(stats, f, indent=2)
            logger.info(f"[EXPORT] Report saved to {filepath}")
            return filepath
        else:
            return json.dumps(stats, indent=2)


def demo():
    """Demo hotspot monitoring"""
    print("\n[*] Hotspot Monitor Demo\n")
    
    monitor = HotspotMonitor()
    
    print("[*] Simulating connected devices...\n")
    
    # Add test clients
    clients = [
        ("AA:BB:CC:DD:EE:01", "192.168.43.10", "iPhone"),
        ("AA:BB:CC:DD:EE:02", "192.168.43.11", "Android Phone"),
        ("AA:BB:CC:DD:EE:03", "192.168.43.12", "Laptop"),
    ]
    
    for mac, ip, hostname in clients:
        monitor.add_client(mac, ip, hostname)
    
    print("[*] Processing test traffic...\n")
    
    # Simulate normal traffic
    monitor.process_client_packet(
        "AA:BB:CC:DD:EE:01", "iPhone",
        "192.168.43.10", "8.8.8.8",
        "TCP", 54321, 443,
        b"GET / HTTP/1.1\r\nHost: facebook.com", "outgoing"
    )
    
    # Simulate malicious traffic
    monitor.process_client_packet(
        "AA:BB:CC:DD:EE:02", "Android Phone",
        "192.168.43.11", "192.168.43.1",
        "TCP", 54322, 80,
        b"<img src=x onerror=alert('XSS')>", "outgoing"
    )
    
    monitor.process_client_packet(
        "AA:BB:CC:DD:EE:03", "Laptop",
        "10.0.0.5", "192.168.43.12",
        "TCP", 54323, 3306,
        b"SELECT * FROM users WHERE id=1 OR 1=1--", "incoming"
    )
    
    # Generate report
    print(monitor.generate_report())
    
    # Export results
    monitor.export_json("/tmp/hotspot_results.json")


if __name__ == "__main__":
    demo()

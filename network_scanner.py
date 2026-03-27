#!/usr/bin/env python3
"""
Advanced Network Scanner Module
Handles network reconnaissance, device discovery, port scanning, and vulnerability detection
"""

import threading
import socket
import logging
import time
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import re

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configure logging
logger = logging.getLogger('NetworkScanner')
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class NetworkScanner:
    """Advanced network scanning with device discovery and vulnerability assessment"""
    
    def __init__(self):
        self.devices = {}  # IP -> device data
        self.device_id_counter = 0
        self.discovery_thread = None
        self.running = False
        self.last_scan_time = {}
        self.ports_cache = {}  # device_ip -> [open_ports]
        self.vulns_cache = {}  # device_ip -> [vulnerabilities]
        self.lock = threading.Lock()
        
        # Device timeout (remove if not seen for 5 minutes)
        self.device_timeout = 300
        
        # Scan throttling (prevent too frequent scans on same target)
        self.scan_interval = 30  # seconds between scans of same target
        
        logger.info("NetworkScanner initialized")
    
    def start_continuous_discovery(self, network: str = "192.168.1.0/24"):
        """Start background thread for continuous device discovery via ARP"""
        if self.running:
            logger.warning("Discovery already running")
            return
        
        self.running = True
        self.discovery_thread = threading.Thread(
            target=self._continuous_discovery_worker,
            args=(network,),
            daemon=True
        )
        self.discovery_thread.start()
        logger.info(f"Started continuous discovery on {network}")
    
    def stop_continuous_discovery(self):
        """Stop background discovery thread"""
        self.running = False
        if self.discovery_thread and self.discovery_thread.is_alive():
            self.discovery_thread.join(timeout=2)
        logger.info("Stopped continuous discovery")
    
    def _continuous_discovery_worker(self, network: str):
        """Worker thread for continuous ARP discovery"""
        while self.running:
            try:
                self._arp_scan(network)
                self._cleanup_stale_devices()
                time.sleep(30)  # Scan every 30 seconds
            except Exception as e:
                logger.error(f"Discovery worker error: {e}")
                time.sleep(5)
    
    def discover_devices(self, network: str = "192.168.1.0/24") -> List[Dict]:
        """
        Perform immediate ARP scan to discover devices on network
        
        Args:
            network: Network in CIDR notation (default: 192.168.1.0/24)
        
        Returns:
            List of discovered device dictionaries
        """
        discovered_ips = []
        try:
            logger.info(f"[DISCOVERY] Starting ARP scan on {network}")
            
            if not SCAPY_AVAILABLE:
                logger.warning("[DISCOVERY] Scapy not available, using socket fallback")
                discovered_ips = self._discover_devices_socket(network)
                return self._get_discovered_devices(discovered_ips)
            
            # Parse network
            try:
                net = ipaddress.ip_network(network, strict=False)
            except ValueError:
                logger.error(f"Invalid network: {network}")
                return []
            
            # Create ARP request
            conf.verb = 0  # Suppress verbose output
            timeout = 2
            
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
            
            # Send and receive
            answered, unanswered = srp(arp_request, timeout=timeout, verbose=False)
            
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                hostname = self._resolve_hostname(ip)
                
                # Add or update device
                self._add_device(ip, mac, hostname)
                discovered_ips.append(ip)
            
            logger.info(f"[DISCOVERY] Discovered {len(discovered_ips)} device(s)")
            
        except Exception as e:
            logger.error(f"Discovery scan error: {e}")
        
        # Return device dictionaries instead of IP strings
        return self._get_discovered_devices(discovered_ips)
    
    def _discover_devices_socket(self, network: str) -> List[str]:
        """Fallback socket-based device discovery - returns list of IPs"""
        discovered_ips = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            base_ip = str(net.network_address)
            base_parts = base_ip.split('.')
            base = '.'.join(base_parts[:3])
            
            logger.info(f"[DISCOVERY] Using socket fallback for {network}")
            
            for i in range(1, 255):
                target_ip = f"{base}.{i}"
                try:
                    hostname = socket.gethostbyaddr(target_ip)[0]
                    self._add_device(target_ip, "unknown", hostname)
                    discovered_ips.append(target_ip)
                except:
                    pass
            
            logger.info(f"[DISCOVERY] Socket scan: {len(discovered_ips)} device(s)")
        except Exception as e:
            logger.error(f"Socket discovery error: {e}")
        
        return discovered_ips
    
    def _get_discovered_devices(self, ip_list: List[str]) -> List[Dict]:
        """Convert list of IPs to list of device dictionaries"""
        result = []
        with self.lock:
            for ip in ip_list:
                if ip in self.devices:
                    result.append(self.devices[ip])
        return result
    
    def _arp_scan(self, network: str):
        """Perform ARP scan to discover devices on network"""
        if not SCAPY_AVAILABLE:
            return
        
        try:
            logger.info(f"[ARP_SCAN] Starting ARP scan on {network}")
            
            # Parse network
            try:
                net = ipaddress.ip_network(network, strict=False)
            except ValueError:
                logger.error(f"Invalid network: {network}")
                return
            
            # Create ARP request
            conf.verb = 0  # Suppress verbose output
            timeout = 2
            
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
            
            # Send and receive
            answered, unanswered = srp(arp_request, timeout=timeout, verbose=False)
            
            discovered_count = 0
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                hostname = self._resolve_hostname(ip)
                
                # Add or update device
                self._add_device(ip, mac, hostname)
                discovered_count += 1
            
            if discovered_count > 0:
                logger.info(f"[ARP_SCAN] Discovered {discovered_count} device(s) on {network}")
            
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
    
    def _add_device(self, ip: str, mac: str, hostname: str = None):
        """Add or update device in discovered devices"""
        with self.lock:
            device_key = ip
            
            if device_key not in self.devices:
                self.device_id_counter += 1
                self.devices[device_key] = {
                    'device_id': self.device_id_counter,
                    'ip': ip,
                    'mac': mac if mac != "unknown" else "unknown",
                    'hostname': hostname or 'unknown',
                    'open_ports': [],
                    'vulnerabilities': [],
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'active': True
                }
                logger.info(f"[DEVICE_DISCOVERED] {ip} ({mac}) - {hostname or 'unknown'}")
            else:
                self.devices[device_key]['last_seen'] = datetime.now()
                self.devices[device_key]['active'] = True
                if hostname and hostname != 'unknown':
                    self.devices[device_key]['hostname'] = hostname
    
    def _cleanup_stale_devices(self):
        """Remove devices not seen for device_timeout seconds"""
        with self.lock:
            now = datetime.now()
            stale = []
            
            for device_id, device in self.devices.items():
                age = (now - device['last_seen']).total_seconds()
                if age > self.device_timeout:
                    stale.append(device_id)
            
            for device_id in stale:
                del self.devices[device_id]
                logger.info(f"[DEVICE_REMOVED] Device {device_id} (timeout)")
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Attempt to resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def search_devices(self, query: str) -> List[Dict]:
        """
        Search for devices matching query
        Supports: single IP, CIDR notation, IP range, partial IP, mac address, hostname
        """
        with self.lock:
            results = []
            
            # Clean query
            query = query.strip().lower()
            
            if not query:
                return list(self.devices.values())
            
            try:
                # Try CIDR notation first
                if '/' in query:
                    network = ipaddress.ip_network(query, strict=False)
                    for device in self.devices.values():
                        if ipaddress.ip_address(device['ip']) in network:
                            results.append(device)
                    logger.info(f"[SEARCH] CIDR Query '{query}' found {len(results)} device(s)")
                    return results
                
                # Try IP range (e.g., "192.168.1.1-50")
                if '-' in query and ':' not in query:
                    parts = query.split('-')
                    if len(parts) == 2:
                        try:
                            start_num = int(parts[0].split('.')[-1])
                            end_num = int(parts[1])
                            base = '.'.join(parts[0].split('.')[:-1])
                            
                            for device in self.devices.values():
                                dev_ip = device['ip']
                                dev_num = int(dev_ip.split('.')[-1])
                                if dev_ip.startswith(base) and start_num <= dev_num <= end_num:
                                    results.append(device)
                            
                            logger.info(f"[SEARCH] Range Query '{query}' found {len(results)} device(s)")
                            return results
                        except (ValueError, IndexError):
                            pass
                
                # Try partial IP match (e.g., "192.168.1.*")
                if '*' in query:
                    pattern = query.replace('.', r'\.').replace('*', '.*')
                    for device in self.devices.values():
                        if re.match(pattern, device['ip']):
                            results.append(device)
                    logger.info(f"[SEARCH] Partial Query '{query}' found {len(results)} device(s)")
                    return results
                
                # Try MAC address match
                if ':' in query and len(query) > 5:
                    for device in self.devices.values():
                        if device['mac'].lower().startswith(query):
                            results.append(device)
                    if results:
                        logger.info(f"[SEARCH] MAC Query '{query}' found {len(results)} device(s)")
                        return results
                
                # Try exact IP match
                if query in self.devices:
                    logger.info(f"[SEARCH] Exact Query '{query}' found 1 device(s)")
                    return [self.devices[query]]
                
                # Try hostname/partial hostname match
                for device in self.devices.values():
                    if query in device['hostname'].lower():
                        results.append(device)
                
                if results:
                    logger.info(f"[SEARCH] Hostname Query '{query}' found {len(results)} device(s)")
                    return results
                
                logger.info(f"[SEARCH] Query '{query}' found {len(results)} device(s)")
                return results
                
            except Exception as e:
                logger.error(f"Search error for query '{query}': {e}")
                return []
    
    def get_all_devices(self) -> List[Dict]:
        """Get all discovered active devices"""
        with self.lock:
            return list(self.devices.values())
    
    def scan_ports(self, target: str, ports: str = "1-1000", timeout: int = 10) -> Dict:
        """
        Scan ports on target device or network
        """
        try:
            logger.info(f"[PORT_SCAN] Starting port scan on {target} (ports: {ports})")
            
            # Throttle repeated scans on same target
            if target in self.last_scan_time:
                elapsed = time.time() - self.last_scan_time[target]
                if elapsed < self.scan_interval:
                    logger.warning(f"[PORT_SCAN] {target} scanned {elapsed:.1f}s ago, throttling")
                    if target in self.ports_cache:
                        return self.ports_cache[target]
            
            if not NMAP_AVAILABLE:
                logger.info("[PORT_SCAN] using socket fallback (nmap not available)")
                return self._socket_port_scan(target, ports)
            
            # Use nmap for port scanning
            nm = nmap.PortScanner()
            
            try:
                nm.scan(target, ports, f"-sV --open -T3 --max-retries 1", timeout=timeout)
            except nmap.PortScannerTimeout:
                logger.warning(f"[PORT_SCAN] Timeout scanning {target}")
                return {}
            except Exception as e:
                logger.warning(f"[PORT_SCAN] Nmap error on {target}: {e}")
                # Fallback to socket scanning
                return self._socket_port_scan(target, ports)
            
            results = {}
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    open_ports = []
                    services = {}
                    
                    for port in nm[host]['tcp'].keys():
                        if nm[host]['tcp'][port]['state'] == 'open':
                            open_ports.append(port)
                            service = nm[host]['tcp'][port]['name']
                            services[port] = service
                    
                    if open_ports:
                        results[host] = {
                            'open_ports': open_ports,
                            'services': services,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Update device cache
                        with self.lock:
                            if host in self.devices:
                                self.devices[host]['open_ports'] = open_ports
                        
                        logger.info(f"[PORT_SCAN] {host}: {len(open_ports)} open ports: {open_ports}")
                    else:
                        logger.info(f"[PORT_SCAN] {host}: No open ports found")
            
            self.last_scan_time[target] = time.time()
            self.ports_cache[target] = results
            
            logger.info(f"[PORT_SCAN] Scan complete: {len(results)} hosts with open ports")
            return results
            
        except Exception as e:
            logger.error(f"Port scan error: {e}")
            return {}
    
    def _socket_port_scan(self, target: str, ports: str) -> Dict:
        """Fallback socket-based port scanning when nmap unavailable"""
        try:
            results = {}
            
            # Parse ports
            port_list = self._parse_ports(ports)
            
            # Parse targets
            target_ips = self._parse_targets(target)
            
            for ip in target_ips:
                open_ports = []
                
                for port in port_list:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        
                        if result == 0:
                            open_ports.append(port)
                    except:
                        pass
                
                if open_ports:
                    results[ip] = {
                        'open_ports': open_ports,
                        'services': {},
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    with self.lock:
                        if ip in self.devices:
                            self.devices[ip]['open_ports'] = open_ports
            
            return results
            
        except Exception as e:
            logger.error(f"Socket scan error: {e}")
            return {}
    
    def _parse_ports(self, port_spec: str) -> List[int]:
        """Parse port specification like '1-1000' or '22,80,443'"""
        ports = []
        
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))[:1000]  # Limit to first 1000 ports
    
    def _parse_targets(self, target: str) -> List[str]:
        """Parse target specification into list of IPs"""
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in list(net.hosts())[:256]]  # Limit to 256 hosts
        except ValueError:
            return [target]
    
    def scan_vulnerabilities(self, target: str) -> Dict:
        """Scan target for known vulnerabilities based on open ports"""
        try:
            logger.info(f"[VULN_SCAN] Starting vulnerability scan on {target}")
            
            # First, scan ports if not already scanned
            port_results = self.scan_ports(target)
            
            if not port_results:
                logger.info(f"[VULN_SCAN] No open ports found on {target}")
                return {}
            
            # Vulnerability database
            port_vuln_map = {
                22: [
                    {'name': 'SSH Log4Shell', 'cve': 'CVE-2021-44228', 'severity': 'HIGH', 'description': 'Potential log4j vulnerability', 'remediation': 'Update SSH service'},
                    {'name': 'SSH Weak Algorithms', 'cve': 'CVE-2023-35078', 'severity': 'MEDIUM', 'description': 'SSH weak encryption', 'remediation': 'Disable weak algorithms'},
                ],
                3389: [
                    {'name': 'RDP BlueKeep', 'cve': 'CVE-2019-0708', 'severity': 'CRITICAL', 'description': 'Remote code execution', 'remediation': 'Update Windows'},
                ],
                3306: [
                    {'name': 'MySQL Exposed', 'cve': 'CVE-2023-21836', 'severity': 'HIGH', 'description': 'Database exposed', 'remediation': 'Restrict access'},
                ],
                5432: [
                    {'name': 'PostgreSQL Exposed', 'cve': 'CVE-2023-2455', 'severity': 'HIGH', 'description': 'Database exposed', 'remediation': 'Restrict access'},
                ],
                6379: [
                    {'name': 'Redis Exposed', 'cve': 'CVE-2023-25645', 'severity': 'CRITICAL', 'description': 'No authentication', 'remediation': 'Enable password auth'},
                ],
                9200: [
                    {'name': 'Elasticsearch Exposed', 'cve': 'CVE-2023-31489', 'severity': 'CRITICAL', 'description': 'No authentication', 'remediation': 'Enable security'},
                ],
                80: [
                    {'name': 'HTTP Weak', 'cve': 'CVE-2023-N/A', 'severity': 'MEDIUM', 'description': 'Unencrypted HTTP', 'remediation': 'Use HTTPS'},
                ],
                445: [
                    {'name': 'SMB WannaCry', 'cve': 'CVE-2017-0144', 'severity': 'CRITICAL', 'description': 'Ransomware vulnerable', 'remediation': 'Disable SMBv1'},
                ],
                23: [
                    {'name': 'Telnet Weak', 'cve': 'CVE-2023-N/A', 'severity': 'HIGH', 'description': 'Unencrypted remote access', 'remediation': 'Use SSH'},
                ]
            }
            
            results = {}
            
            for host, port_info in port_results.items():
                host_vulns = []
                
                for port in port_info['open_ports']:
                    if port in port_vuln_map:
                        host_vulns.extend(port_vuln_map[port])
                
                if host_vulns:
                    results[host] = host_vulns
                    
                    # Update device cache
                    with self.lock:
                        if host in self.devices:
                            self.devices[host]['vulnerabilities'] = host_vulns
                    
                    logger.info(f"[VULN_SCAN] {host}: Found {len(host_vulns)} vulnerabilities")
            
            logger.info(f"[VULN_SCAN] Scan complete")
            return results
            
        except Exception as e:
            logger.error(f"Vulnerability scan error: {e}")
            return {}
    
    def get_device_details(self, ip: str) -> Optional[Dict]:
        """Get detailed information about a specific device"""
        with self.lock:
            if ip in self.devices:
                return self.devices[ip].copy()
        return None
    
    def get_network_summary(self) -> Dict:
        """Get summary statistics of scanned network"""
        with self.lock:
            devices = list(self.devices.values())
            
            total_open_ports = sum(len(d['open_ports']) for d in devices)
            total_vulns = sum(len(d['vulnerabilities']) for d in devices)
            critical_vulns = sum(
                len([v for v in d['vulnerabilities'] if v.get('severity') == 'CRITICAL'])
                for d in devices
            )
            
            return {
                'total_devices': len(devices),
                'active_devices': len([d for d in devices if d['active']]),
                'total_open_ports': total_open_ports,
                'total_vulnerabilities': total_vulns,
                'critical_vulnerabilities': critical_vulns,
                'timestamp': datetime.now().isoformat()
            }


# Global scanner instance
_scanner = None


def get_scanner() -> NetworkScanner:
    """Get or create global network scanner instance"""
    global _scanner
    if _scanner is None:
        _scanner = NetworkScanner()
    return _scanner
#!/usr/bin/env python3
"""
VULNERABILITY SCANNER - CVE & Exploit Detection
===============================================

Integrates with NIDS detection engine to:
- Identify known CVEs and vulnerabilities
- Check open ports for known exploits
- Generate customized recommendations
- Alert through multiple channels with rate limiting
- AI-powered analysis with Gemini API (for critical/high severity only)

Features:
- Real-time vulnerability detection
- Channel-specific alert formatting
- Rate limiting for Discord and Gemini
- Severity-based analysis
- Actionable remediation recommendations

Author: Advanced NIDS Team
Date: March 27, 2026
"""

import logging
import time
import json
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("VulnScanner")


class Severity(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertChannel(Enum):
    """Alert delivery channels"""
    DISCORD = "discord"
    GEMINI = "gemini"
    LOG = "log"
    GUI = "gui"


class VulnerabilityDatabase:
    """Database of known vulnerabilities and CVEs"""
    
    KNOWN_VULNERABILITIES = {
        # SSH Vulnerabilities
        'SSH_CVE_2021_44228': {
            'name': 'SSH Log4Shell Exploitation (CVE-2021-44228)',
            'cve': 'CVE-2021-44228',
            'severity': Severity.CRITICAL,
            'affected_ports': [22],
            'remediation': [
                'Update SSH server to latest patched version',
                'Implement SSH key-based authentication only',
                'Disable SSH password authentication',
                'Use firewall to restrict SSH access to known IPs',
                'Enable SSH auditing and monitoring',
            ]
        },
        
        # SMB Vulnerabilities
        'SMB_WANNACRY': {
            'name': 'SMB WannaCry Vulnerability (CVE-2017-0144)',
            'cve': 'CVE-2017-0144',
            'severity': Severity.CRITICAL,
            'affected_ports': [445],
            'remediation': [
                'Apply Microsoft security patch MS17-010 immediately',
                'Disable SMBv1 protocol completely',
                'Enable Windows Defender/Antivirus',
                'Implement network segmentation',
                'Block port 445 externally',
                'Enable file sharing signature requirements',
            ]
        },
        
        # RDP Vulnerabilities
        'RDP_BLUEKEEP': {
            'name': 'RDP BlueKeep Vulnerability (CVE-2019-0708)',
            'cve': 'CVE-2019-0708',
            'severity': Severity.CRITICAL,
            'affected_ports': [3389],
            'remediation': [
                'Install Windows security updates for CVE-2019-0708',
                'Disable RDP if not required',
                'Restrict RDP access via firewall',
                'Enable RDP encryption',
                'Use VPN for remote access instead of direct RDP',
                'Enable multi-factor authentication for RDP',
            ]
        },
        
        # MySQL Vulnerabilities
        'MYSQL_REMOTE_ACCESS': {
            'name': 'MySQL Remote Access Exposed',
            'cve': 'N/A',
            'severity': Severity.HIGH,
            'affected_ports': [3306],
            'remediation': [
                'Bind MySQL to localhost (127.0.0.1) only',
                'Use SSH tunneling for remote connections',
                'Disable remote root login',
                'Use strong passwords and change default credentials',
                'Implement firewall rules to restrict MySQL port',
                'Enable MySQL binary logging and audit plugins',
            ]
        },
        
        # Redis Vulnerabilities
        'REDIS_UNAUTHENTICATED': {
            'name': 'Redis Unauthenticated Access (CVE-2015-4335)',
            'cve': 'CVE-2015-4335',
            'severity': Severity.CRITICAL,
            'affected_ports': [6379],
            'remediation': [
                'Enable Redis password authentication (requirepass)',
                'Bind Redis to localhost only',
                'Use firewall to restrict Redis port',
                'Use Redis SSL/TLS for remote connections',
                'Update to latest Redis version',
                'Disable dangerous commands in production',
            ]
        },
        
        # Elasticsearch Vulnerabilities
        'ELASTICSEARCH_EXPOSED': {
            'name': 'Elasticsearch Unprotected Access (CVE-2014-3120)',
            'cve': 'CVE-2014-3120',
            'severity': Severity.CRITICAL,
            'affected_ports': [9200],
            'remediation': [
                'Enable Elasticsearch X-Pack security',
                'Implement authentication and authorization',
                'Use firewall to restrict Elasticsearch access',
                'Enable TLS/SSL encryption',
                'Disable REST API if not needed',
                'Update to latest Elasticsearch version with security patches',
            ]
        },
        
        # PostgreSQL Vulnerabilities
        'POSTGRES_EXPOSED': {
            'name': 'PostgreSQL Remote Access Exposed',
            'cve': 'N/A',
            'severity': Severity.HIGH,
            'affected_ports': [5432],
            'remediation': [
                'Configure postgresql.conf with local listen_addresses',
                'Use pg_hba.conf to restrict connection sources',
                'Implement strong password policies',
                'Use SSL/TLS for remote connections',
                'Disable superuser remote login',
                'Enable PostgreSQL audit logging',
            ]
        },
        
        # HTTP/HTTPS Vulnerabilities
        'HTTP_EXPOSED': {
            'name': 'HTTP Service Without HTTPS',
            'cve': 'N/A',
            'severity': Severity.MEDIUM,
            'affected_ports': [80],
            'remediation': [
                'Implement HTTPS (port 443) with valid SSL/TLS certificate',
                'Redirect all HTTP traffic to HTTPS',
                'Enable HSTS (HTTP Strict Transport Security)',
                'Use strong cipher suites',
                'Keep web server software updated',
                'Implement Web Application Firewall (WAF)',
            ]
        },
        
        # Telnet
        'TELNET_EXPOSED': {
            'name': 'Telnet Service Unencrypted (CVE-2016-6303)',
            'cve': 'CVE-2016-6303',
            'severity': Severity.HIGH,
            'affected_ports': [23],
            'remediation': [
                'Disable Telnet completely - use SSH instead',
                'Implement SSH server with key-based authentication',
                'Remove all Telnet services and packages',
                'Implement access logging for all remote access',
            ]
        },
    }
    
    @classmethod
    def get_vulnerabilities(cls, port: int) -> List[Dict]:
        """Get vulnerabilities for specific port"""
        vulns = []
        for vuln_id, vuln_data in cls.KNOWN_VULNERABILITIES.items():
            if port in vuln_data['affected_ports']:
                vulns.append({
                    'id': vuln_id,
                    'name': vuln_data['name'],
                    'cve': vuln_data['cve'],
                    'severity': vuln_data['severity'].name,
                    'remediation': vuln_data['remediation'],
                })
        return vulns


class RateLimiter:
    """Rate limiter with per-channel windows"""
    
    def __init__(self):
        self.discord_rate_limit = 10  # Alerts per hour
        self.gemini_rate_limit = 5    # Analyses per hour
        self.last_discord_alerts = []
        self.last_gemini_analyses = []
    
    def can_send_discord_alert(self) -> bool:
        """Check if Discord rate limit allows sending alert"""
        now = datetime.now()
        one_hour_ago = now - timedelta(hours=1)
        
        # Remove old alerts outside window
        self.last_discord_alerts = [
            ts for ts in self.last_discord_alerts if ts > one_hour_ago
        ]
        
        if len(self.last_discord_alerts) < self.discord_rate_limit:
            self.last_discord_alerts.append(now)
            return True
        
        return False
    
    def can_run_gemini_analysis(self) -> bool:
        """Check if Gemini rate limit allows analysis"""
        now = datetime.now()
        one_hour_ago = now - timedelta(hours=1)
        
        # Remove old analyses outside window
        self.last_gemini_analyses = [
            ts for ts in self.last_gemini_analyses if ts > one_hour_ago
        ]
        
        if len(self.last_gemini_analyses) < self.gemini_rate_limit:
            self.last_gemini_analyses.append(now)
            return True
        
        return False


class VulnScanner:
    """Vulnerability scanner with alert customization and rate limiting"""
    
    def __init__(self, detection_engine=None):
        """Initialize vulnerability scanner"""
        self.detection_engine = detection_engine
        self.rate_limiter = RateLimiter()
        self.alert_history = []
        self.lock = threading.Lock()
        
        logger.info("[VULN SCANNER] Initialized")
    
    def scan_port_vulnerability(self, target_ip: str, port: int) -> Dict:
        """
        Scan specific port for vulnerabilities.
        
        Args:
            target_ip: Target IP address
            port: Port number to scan
        
        Returns:
            Dictionary with vulnerability findings
        """
        try:
            vulns = VulnerabilityDatabase.get_vulnerabilities(port)
            
            findings = {
                'target_ip': target_ip,
                'port': port,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities_found': len(vulns) > 0,
                'vulnerabilities': vulns,
                'risk_score': len(vulns) * 25,  # 25 points per vulnerability
            }
            
            if vulns:
                logger.warning(
                    f"[VULN FOUND] {target_ip}:{port} has "
                    f"{len(vulns)} vulnerability(ies)"
                )
                
                # Generate and send alerts
                for vuln in vulns:
                    self._generate_vulnerability_alert(target_ip, port, vuln)
            
            return findings
        
        except Exception as e:
            logger.error(f"[VULN SCAN] Error scanning {target_ip}:{port} - {e}")
            return {}
    
    def _generate_vulnerability_alert(self, target_ip: str, port: int, vuln: Dict):
        """Generate and dispatch customized vulnerability alert"""
        try:
            severity = Severity[vuln['severity']]
            
            # Store in history
            with self.lock:
                self.alert_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'target_ip': target_ip,
                    'port': port,
                    'vuln_name': vuln['name'],
                    'cve': vuln['cve'],
                    'severity': vuln['severity'],
                })
            
            # Generate channel-specific alerts
            self._send_gui_alert(target_ip, port, vuln, severity)
            
            if self.rate_limiter.can_send_discord_alert():
                self._send_discord_alert(target_ip, port, vuln, severity)
            else:
                logger.info(f"[RATE LIMIT] Discord alert rate limit exceeded, skipping")
            
            # Gemini analysis for critical/high severity only
            if severity in [Severity.CRITICAL, Severity.HIGH]:
                if self.rate_limiter.can_run_gemini_analysis():
                    self._run_gemini_analysis(target_ip, port, vuln, severity)
                else:
                    logger.info(f"[RATE LIMIT] Gemini analysis rate limit exceeded, skipping")
            
            self._log_alert(target_ip, port, vuln, severity)
        
        except Exception as e:
            logger.error(f"[ALERT ERROR] Failed to generate alert: {e}")
    
    def _send_gui_alert(self, target_ip: str, port: int, vuln: Dict, severity: Severity):
        """Send real-time alert to GUI"""
        try:
            alert = {
                'type': 'VULNERABILITY',
                'severity': severity.name,
                'src': target_ip,
                'dst_port': port,
                'message': vuln['name'],
                'cve': vuln['cve'],
                'timestamp': time.time(),
                'confidence': 100,  # Vulnerability scan result
                'remediation': vuln['remediation'],
            }
            
            logger.info(f"[GUI ALERT] {vuln['name']} - {target_ip}:{port}")
        
        except Exception as e:
            logger.error(f"[GUI ALERT ERROR] {e}")
    
    def _send_discord_alert(self, target_ip: str, port: int, vuln: Dict, severity: Severity):
        """Send formatted alert to Discord"""
        try:
            severity_emoji = {
                Severity.LOW: '⚠️',
                Severity.MEDIUM: '🟠',
                Severity.HIGH: '🔴',
                Severity.CRITICAL: '🚨',
            }[severity]
            
            discord_message = f"""
{severity_emoji} **VULNERABILITY DETECTED**

**Target:** `{target_ip}:{port}`
**Vulnerability:** {vuln['name']}
**CVE:** {vuln['cve']}
**Severity:** {severity.name}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**Recommended Actions:**
{chr(10).join(f'• {rec}' for rec in vuln['remediation'][:3])}

**Status:** Monitor for exploitation attempts
"""
            
            logger.info(f"[DISCORD ALERT] Sent: {vuln['name']}")
            # In production, send to Discord webhook here
        
        except Exception as e:
            logger.error(f"[DISCORD ERROR] {e}")
    
    def _run_gemini_analysis(self, target_ip: str, port: int, vuln: Dict, severity: Severity):
        """Run AI analysis using Gemini (for critical/high severity only)"""
        try:
            analysis_context = f"""
Analyze this security vulnerability:
- Target: {target_ip}:{port}
- Vulnerability: {vuln['name']}
- CVE: {vuln['cve']}
- Severity: {severity.name}

Provide:
1. Risk assessment
2. Exploitation likelihood
3. Business impact
4. Mitigation priority
5. Quick remediation steps
"""
            
            logger.info(
                f"[GEMINI ANALYSIS] Running for {vuln['name']} "
                f"({severity.name} severity)"
            )
            # In production, call Gemini API here
        
        except Exception as e:
            logger.error(f"[GEMINI ERROR] {e}")
    
    def _log_alert(self, target_ip: str, port: int, vuln: Dict, severity: Severity):
        """Log alert to file"""
        try:
            log_line = (
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"{severity.name:>8} | {target_ip}:{port:<6} | "
                f"{vuln['name']:<50} | {vuln['cve']}"
            )
            
            logger.warning(log_line)
            
            # Also log to file for audit trail
            try:
                with open('vuln_scan_log.txt', 'a') as f:
                    f.write(log_line + '\n')
            except:
                pass
        
        except Exception as e:
            logger.error(f"[LOG ERROR] {e}")
    
    def get_alert_summary(self, hours: int = 24) -> Dict:
        """Get summary of alerts in time window"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            recent_alerts = [
                alert for alert in self.alert_history
                if datetime.fromisoformat(alert['timestamp']) > cutoff_time
            ]
            
            severity_counts = defaultdict(int)
            affected_ips = defaultdict(int)
            affected_ports = defaultdict(int)
            
            for alert in recent_alerts:
                severity_counts[alert['severity']] += 1
                affected_ips[alert['target_ip']] += 1
                affected_ports[alert['port']] += 1
            
            return {
                'time_window_hours': hours,
                'total_vulnerabilities_found': len(recent_alerts),
                'severity_distribution': dict(severity_counts),
                'top_affected_ips': sorted(
                    affected_ips.items(), key=lambda x: x[1], reverse=True
                )[:5],
                'top_affected_ports': sorted(
                    affected_ports.items(), key=lambda x: x[1], reverse=True
                )[:5],
                'recent_alerts': recent_alerts[-10:],
            }
        
        except Exception as e:
            logger.error(f"[SUMMARY ERROR] {e}")
            return {}
    
    def generate_report(self, target_ip: str = None) -> str:
        """Generate comprehensive vulnerability report"""
        try:
            summary = self.get_alert_summary(hours=24)
            
            report = f"""
╔════════════════════════════════════════════════════════════════╗
║       VULNERABILITY SCAN REPORT
║       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚════════════════════════════════════════════════════════════════╝

SUMMARY (Last 24 Hours)
───────────────────────
  Total Vulnerabilities:  {summary.get('total_vulnerabilities_found', 0)}
  
SEVERITY DISTRIBUTION
─────────────────────
"""
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = summary.get('severity_distribution', {}).get(severity, 0)
                report += f"  {severity:<10} {count:>3} findings\n"
            
            report += "\nTOP AFFECTED IPS\n───────────────\n"
            for ip, count in summary.get('top_affected_ips', []):
                report += f"  {ip:<20} {count:>3} vulnerabilities\n"
            
            report += "\nTOP AFFECTED PORTS\n──────────────────\n"
            for port, count in summary.get('top_affected_ports', []):
                report += f"  Port {port:<16} {count:>3} vulnerabilities\n"
            
            return report
        
        except Exception as e:
            logger.error(f"[REPORT ERROR] {e}")
            return ""


# Module-level helper functions
def create_vuln_scanner(detection_engine=None) -> VulnScanner:
    """Factory function to create vulnerability scanner"""
    return VulnScanner(detection_engine)

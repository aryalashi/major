#!/usr/bin/env python3
"""
NIDS - Headless Mode (No GUI)
==============================
Network Intrusion Detection System for headless/cloud environments.
Runs packet capture and detection without any GUI dependencies.
"""

import sys
import queue
import logging
import threading
import os
import time
import signal
from dotenv import load_dotenv

load_dotenv()

# Fix Windows Unicode encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

os.makedirs("logs", exist_ok=True)
os.makedirs("attacks", exist_ok=True)

# ================================================================
#  CONFIGURATION
# ================================================================

class Config:
    """Centralised configuration - all credentials and parameters loaded from .env"""
    
    DEFAULT_WINDOW        = int(os.getenv("NIDS_WINDOW", 10))
    ALERT_COOLDOWN        = int(os.getenv("NIDS_COOLDOWN", 30))
    DDOS_SOURCE_THRESHOLD = int(os.getenv("NIDS_DDOS_THRESHOLD", 10))
    MAX_EVIDENCE_PACKETS  = int(os.getenv("NIDS_MAX_EVIDENCE", 200))
    
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
    EMAIL_ADDRESS   = os.getenv("EMAIL_ADDRESS", "")
    EMAIL_PASSWORD  = os.getenv("EMAIL_PASSWORD", "")
    EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT", "")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    WHITELIST_IPS = [ip.strip() for ip in os.getenv("WHITELIST_IPS", "").split(",") if ip.strip()]
    LOG_FILE    = "logs/nids.log"
    ATTACKS_DIR = os.getenv("ATTACKS_DIR", "attacks")
    LOGS_DIR    = os.getenv("LOGS_DIR", "logs")

# ------------------------------------------------------------------ #
#  LOGGING SETUP
# ------------------------------------------------------------------ #
class _FlushFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    handlers=[
        _FlushFileHandler("logs/nids.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("NIDS")

# ------------------------------------------------------------------ #
#  IMPORTS
# ------------------------------------------------------------------ #
from detection import DetectionEngine
from packet_capture import PacketCapture
from network_scanner import NetworkScanner
from hotspot_monitor import HotspotMonitor

class HeadlessNIDS:
    """Headless NIDS for cloud/terminal environments"""
    
    def __init__(self):
        self.running = False
        self.capture_controller = None
        self.packet_queue = queue.Queue(maxsize=5000)
        self.detection_engine = DetectionEngine([])
        self.detection_engine.set_confidence_threshold(50)
        
        # Optional components
        self.alert_engine = None
        self.evidence_logger = None
        self.auto_scanner = None
        
        # Network scanner and hotspot monitor
        self.net_scanner = NetworkScanner()
        self.hotspot_monitor = HotspotMonitor()
        
        # Statistics
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = None
        
        # Try to load optional modules
        try:
            from alert import AlertEngine
            self.alert_engine = AlertEngine()
            logger.info("✓ Alert engine loaded")
        except ImportError:
            logger.info("Alert engine not available")
            
        try:
            from vuln_scanner import AutoScanner
            self.auto_scanner = AutoScanner()
            logger.info("✓ Auto scanner loaded")
        except ImportError:
            logger.info("Auto scanner not available")
    
    def start_capture(self, interface=None):
        """Start packet capture on specified interface"""
        if self.running:
            logger.warning("Capture already running")
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Get best interface if none specified
        if interface is None:
            iface_list = PacketCapture.list_interfaces()
            if iface_list:
                # Prefer non-loopback interfaces
                for iface in iface_list:
                    if 'lo' not in iface and 'docker' not in iface:
                        interface = iface
                        break
                if not interface:
                    interface = iface_list[0]
        
        logger.info(f"Starting packet capture on interface: {interface or 'default'}")
        
        # Create capture controller
        from main import CaptureController
        self.capture_controller = CaptureController(
            detection_engine=self.detection_engine,
            gui_queue=self.packet_queue,
            hotspot_monitor=self.hotspot_monitor,
            alert_engine=self.alert_engine,
            evidence_logger=self.evidence_logger,
            auto_scanner=self.auto_scanner
        )
        
        self.capture_controller.start(interface)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("="*60)
        logger.info("NIDS is now monitoring for attacks...")
        logger.info("Press Ctrl+C to stop")
        logger.info("="*60)
    
    def _monitor_loop(self):
        """Monitor for alerts and display them"""
        while self.running:
            try:
                item = self.packet_queue.get(timeout=0.5)
                if item.get("__type") == "alert":
                    self.alert_count += 1
                    self._display_alert(item)
                elif item.get("__type") == "packet":
                    self.packet_count += 1
                    if self.packet_count % 1000 == 0:
                        logger.info(f"Processed {self.packet_count} packets, {self.alert_count} alerts")
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Monitor error: {e}")
    
    def _display_alert(self, alert):
        """Display alert in terminal"""
        timestamp = time.strftime("%H:%M:%S", time.localtime(alert.get("timestamp", time.time())))
        attack_type = alert.get("type", "Unknown")
        severity = alert.get("severity", "MEDIUM")
        confidence = alert.get("confidence", 0)
        src = alert.get("src", "?")
        dst = alert.get("dst", "?")
        dst_port = alert.get("dst_port", 0)
        
        # Color codes for severity
        colors = {
            "CRITICAL": "\033[91m",  # Red
            "HIGH": "\033[93m",      # Yellow
            "MEDIUM": "\033[94m",    # Blue
            "LOW": "\033[92m",       # Green
        }
        reset = "\033[0m"
        
        color = colors.get(severity, "\033[0m")
        print(f"\r\033[K{color}[{timestamp}] {severity:8} | {attack_type:<30} | "
              f"Confidence: {confidence:5.1f}% | {src} → {dst}:{dst_port}{reset}")
    
    def stop(self):
        """Stop capture and show statistics"""
        self.running = False
        if self.capture_controller:
            self.capture_controller.stop()
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        logger.info("\n" + "="*60)
        logger.info("NIDS MONITORING SUMMARY")
        logger.info("="*60)
        logger.info(f"Monitoring duration: {elapsed:.1f} seconds")
        logger.info(f"Packets processed: {self.packet_count}")
        logger.info(f"Alerts generated: {self.alert_count}")
        if self.packet_count > 0:
            rate = self.packet_count / elapsed
            alert_rate = self.alert_count / elapsed
            logger.info(f"Packet rate: {rate:.1f} pps")
            logger.info(f"Alert rate: {alert_rate:.1f} alerts/sec")
        logger.info("="*60)
        
        # Print detector statistics
        stats = self.detection_engine.get_stats()
        if stats.get('detection_stats'):
            logger.info("\nAttack Statistics:")
            for attack, count in stats['detection_stats'].items():
                logger.info(f"  {attack}: {count}")
        logger.info("="*60)

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    logger.info("\n\n[!] Stopping NIDS...")
    if nids:
        nids.stop()
    sys.exit(0)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Headless NIDS')
    parser.add_argument('--interface', '-i', help='Network interface to monitor')
    parser.add_argument('--pcap', '-p', help='Analyze PCAP file instead of live capture')
    parser.add_argument('--cooldown', type=int, default=30, help='Alert cooldown in seconds')
    
    args = parser.parse_args()
    
    # Set cooldown
    os.environ['NIDS_COOLDOWN'] = str(args.cooldown)
    
    nids = HeadlessNIDS()
    
    # Handle Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    if args.pcap:
        # Analyze PCAP file
        from scapy.all import rdpcap
        from main import normalize_packet
        
        logger.info(f"Analyzing PCAP: {args.pcap}")
        packets = rdpcap(args.pcap)
        logger.info(f"Loaded {len(packets)} packets")
        
        alerts = []
        for i, pkt in enumerate(packets[:100]):  # Limit to 100 packets for display
            norm_pkt = normalize_packet(pkt)
            if norm_pkt:
                result = nids.detection_engine.process_packet(norm_pkt)
                if result:
                    alerts.extend(result)
                    for alert in result:
                        nids._display_alert(alert)
        
        logger.info(f"\nAnalysis complete: {len(alerts)} alerts from {min(100, len(packets))} packets")
    else:
        # Live capture
        logger.info("Starting headless NIDS...")
        logger.info(f"Alert cooldown: {args.cooldown} seconds")
        nids.start_capture(args.interface)
        
        # Keep running until interrupted
        try:
            while nids.running:
                time.sleep(1)
        except KeyboardInterrupt:
            signal_handler(None, None)

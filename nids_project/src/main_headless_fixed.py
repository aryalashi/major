#!/usr/bin/env python3
"""
NIDS - Headless Mode (No GUI)
==============================
Network Intrusion Detection System for headless/cloud environments.
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

os.makedirs("logs", exist_ok=True)
os.makedirs("attacks", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("logs/nids.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("NIDS")

# Imports
from detection import DetectionEngine
from packet_capture import PacketCapture
from network_scanner import NetworkScanner
from hotspot_monitor import HotspotMonitor
from normalization import normalize_packet

class HeadlessNIDS:
    def __init__(self):
        self.running = False
        self.capture_controller = None
        self.packet_queue = queue.Queue(maxsize=5000)
        self.detection_engine = DetectionEngine([])
        self.detection_engine.set_confidence_threshold(30)  # Lower for testing
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = None
        self.net_scanner = NetworkScanner()
        self.hotspot_monitor = HotspotMonitor()
    
    def start_capture(self, interface=None):
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        
        if interface is None:
            iface_list = PacketCapture.list_interfaces()
            if iface_list:
                for iface in iface_list:
                    if 'lo' not in iface and 'docker' not in iface:
                        interface = iface
                        break
                if not interface:
                    interface = iface_list[0]
        
        logger.info(f"Starting capture on: {interface or 'default'}")
        
        from main import CaptureController
        self.capture_controller = CaptureController(
            detection_engine=self.detection_engine,
            gui_queue=self.packet_queue,
            hotspot_monitor=self.hotspot_monitor,
            alert_engine=None,
            evidence_logger=None,
            auto_scanner=None
        )
        
        self.capture_controller.start(interface)
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("="*60)
        logger.info("NIDS MONITORING ACTIVE")
        logger.info("Press Ctrl+C to stop")
        logger.info("="*60)
    
    def _monitor_loop(self):
        while self.running:
            try:
                item = self.packet_queue.get(timeout=0.5)
                if item.get("__type") == "alert":
                    self.alert_count += 1
                    self._display_alert(item)
                elif item.get("__type") == "packet":
                    self.packet_count += 1
            except queue.Empty:
                continue
    
    def _display_alert(self, alert):
        timestamp = time.strftime("%H:%M:%S")
        attack_type = alert.get("type", "Unknown")
        severity = alert.get("severity", "MEDIUM")
        confidence = alert.get("confidence", 0)
        src = alert.get("src", "?")
        dst = alert.get("dst", "?")
        dst_port = alert.get("dst_port", 0)
        
        colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m", "LOW": "\033[92m"}
        reset = "\033[0m"
        color = colors.get(severity, "\033[0m")
        
        print(f"{color}[{timestamp}] {severity:8} | {attack_type:<30} | "
              f"Confidence: {confidence:5.1f}% | {src} → {dst}:{dst_port}{reset}")
    
    def stop(self):
        self.running = False
        if self.capture_controller:
            self.capture_controller.stop()
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        logger.info("\n" + "="*60)
        logger.info("MONITORING SUMMARY")
        logger.info("="*60)
        logger.info(f"Duration: {elapsed:.1f}s | Packets: {self.packet_count} | Alerts: {self.alert_count}")
        if self.packet_count > 0 and elapsed > 0:
            logger.info(f"Rate: {self.packet_count/elapsed:.1f} pps | Alert rate: {self.alert_count/elapsed:.1f}/s")
        logger.info("="*60)

def signal_handler(signum, frame):
    logger.info("\n[!] Stopping...")
    if nids:
        nids.stop()
    sys.exit(0)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Headless NIDS')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--pcap', '-p', help='Analyze PCAP file')
    parser.add_argument('--cooldown', type=int, default=30, help='Alert cooldown')
    
    args = parser.parse_args()
    os.environ['NIDS_COOLDOWN'] = str(args.cooldown)
    
    nids = HeadlessNIDS()
    signal.signal(signal.SIGINT, signal_handler)
    
    if args.pcap:
        # Analyze PCAP
        from scapy.all import rdpcap
        logger.info(f"Analyzing: {args.pcap}")
        packets = rdpcap(args.pcap)
        logger.info(f"Loaded {len(packets)} packets")
        
        alerts = 0
        for i, pkt in enumerate(packets[:100]):
            norm_pkt = normalize_packet(pkt)
            if norm_pkt:
                result = nids.detection_engine.process_packet(norm_pkt)
                if result:
                    alerts += len(result)
                    for alert in result:
                        nids._display_alert(alert)
        
        logger.info(f"\nComplete: {alerts} alerts from {min(100, len(packets))} packets")
    else:
        # Live capture
        logger.info("Starting headless NIDS...")
        nids.start_capture(args.interface)
        try:
            while nids.running:
                time.sleep(1)
        except KeyboardInterrupt:
            signal_handler(None, None)

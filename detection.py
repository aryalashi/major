"""
detection.py - ADVANCED SIGNATURE-BASED DETECTION ENGINE
========================================================

Replaces old sliding-window detection with advanced signature-based detection.

Features:
- Adaptive thresholds (no manual tuning)
- Advanced payload analysis (SQL, XSS, Command injection, Encoding)
- DDoS behavioral signatures
- Port scan detection
- Brute force detection
- 100% signature-based (no machine learning)
- Backward compatible with existing alert format

Architecture:
- Layer 1: Header analysis (TCP flags, protocols)
- Layer 2: Payload analysis (injection attacks)
- Layer 3: Behavioral detection (DDoS patterns)
- Layer 4: Correlation
- Layer 5: Alert scoring with confidence

Author: Advanced NIDS Team
Date: March 27, 2026
"""

import os
import time
import logging
from collections import defaultdict, deque
from typing import List, Optional, Dict
from advanced_detection_engine import AdvancedSignatureDetector

try:
    from main import Config
except ImportError:
    class Config:
        DEFAULT_WINDOW = int(os.getenv("NIDS_WINDOW", 10))
        ALERT_COOLDOWN = int(os.getenv("NIDS_COOLDOWN", 30))
        DDOS_SOURCE_THRESHOLD = int(os.getenv("NIDS_DDOS_THRESHOLD", 20))
        MAX_EVIDENCE_PACKETS = int(os.getenv("NIDS_MAX_EVIDENCE", 200))

logger = logging.getLogger("AdvancedDetectionEngine")

class DetectionEngine:
    """
    Advanced signature-based detection engine.
    
    Drop-in replacement for old detection.py with:
    - Adaptive thresholds
    - Advanced payload analysis
    - DDoS behavioral signatures
    - Backward compatible alert format
    """
    
    def __init__(self, rules: list):
        """
        Initialize detection engine.
        
        Args:
            rules: List of signature rules (for compatibility, not used)
        """
        self.rules = rules
        self.config = Config()
        
        # Initialize advanced detector
        self.advanced_detector = AdvancedSignatureDetector()
        
        # Alert cooldown cache for deduplication
        self.alert_cache: Dict = {}
        self.ddos_alert_cache: Dict = {}
        
        # Confidence threshold (can be adjusted)
        self.confidence_threshold = 50  # % - alerts only if >= this
        
        # Statistics tracking
        self.detection_stats = defaultdict(int)
        self.packet_count = 0
        
        # Keep old interface attributes for GUI compatibility
        self.trackers = defaultdict(lambda: defaultdict(deque))
        self.port_trackers = defaultdict(deque)
        self.dst_src_tracker = defaultdict(deque)
        
        logger.info("[ADVANCED DETECTION] Initialized with adaptive signatures")
    
    def process_packet(self, packet_info: dict) -> List[dict]:
        """
        Process a normalized packet and return alerts.
        
        Args:
            packet_info: Normalized packet dict with keys:
                - src, dst, protocol, flags, dst_port, src_port
                - icmp_type, icmp_code, size, timestamp, payload
        
        Returns:
            List of alert dicts in compatible format
        """
        
        alerts = []
        self.packet_count += 1
        
        # Convert normalized packet to advanced detector format
        packet_dict = self._convert_packet(packet_info)
        
        # Run advanced detection
        raw_alerts = self.advanced_detector.detect_attack(packet_dict)
        
        # Convert alerts to compatible format and filter by confidence
        for raw_alert in raw_alerts:
            # Filter by confidence threshold
            confidence = raw_alert.get('confidence', 0)
            
            if confidence < self.confidence_threshold:
                continue
            
            # Check for duplicate alerts (cooldown)
            if not self._should_alert(raw_alert):
                continue
            
            # Convert to compatible format
            compat_alert = self._convert_alert(raw_alert, packet_info)
            alerts.append(compat_alert)
            
            # Track statistics
            self.detection_stats[raw_alert['attack']] += 1
            
            # Log alert
            logger.warning(
                f"[DETECTION] {raw_alert['attack']} | "
                f"Confidence: {confidence:.1f}% | "
                f"Severity: {raw_alert['severity']} | "
                f"Source: {packet_info.get('src')} | "
                f"Target: {packet_info.get('dst')}"
            )
        
        return alerts
    
    # ─────────────────────────────────────────────────────────────────────────
    # CONVERSION FUNCTIONS
    # ─────────────────────────────────────────────────────────────────────────
    
    def _convert_packet(self, packet_info: dict) -> dict:
        """Convert normalized packet to advanced detector format"""
        
        # Map protocol names to numbers
        protocol_map = {
            "TCP": 6,
            "UDP": 17,
            "ICMP": 1,
        }
        
        protocol_num = protocol_map.get(packet_info.get("protocol", "TCP"), 6)
        
        # Convert flags
        flags = packet_info.get("flags", "")
        if isinstance(flags, set):
            flags = "".join(sorted(flags))
        
        # Build packet dict for advanced detector
        packet_dict = {
            "src_ip": packet_info.get("src", "0.0.0.0"),
            "dst_ip": packet_info.get("dst", "0.0.0.0"),
            "protocol": protocol_num,
            "src_port": packet_info.get("src_port", 0),
            "dst_port": packet_info.get("dst_port", 0),
            "flags": flags,
            "payload": packet_info.get("payload", b""),
            "timestamp": packet_info.get("timestamp", time.time()),
            "ttl": packet_info.get("ttl", 64),
        }
        
        return packet_dict
    
    def _convert_alert(self, raw_alert: dict, packet_info: dict) -> dict:
        """Convert advanced detector alert to compatible format"""
        
        severity_to_priority = {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 3,
            "LOW": 4,
        }
        
        compat_alert = {
            "type": raw_alert.get("attack", "Unknown"),
            "rule_name": raw_alert.get("attack"),
            "severity": raw_alert.get("severity", "MEDIUM"),
            "priority": severity_to_priority.get(raw_alert.get("severity", "MEDIUM"), 3),
            "protocol": packet_info.get("protocol", "Unknown"),
            "source": packet_info.get("src", "0.0.0.0"),
            "src": packet_info.get("src", "0.0.0.0"),
            "target": packet_info.get("dst", "0.0.0.0"),
            "dst": packet_info.get("dst", "0.0.0.0"),
            "src_port": packet_info.get("src_port", 0),
            "dst_port": packet_info.get("dst_port", 0),
            "payload_size": len(packet_info.get("payload", b"")),
            "confidence": raw_alert.get("confidence", 0),
            "timestamp": packet_info.get("timestamp", time.time()),
            "layer": raw_alert.get("layer", "Unknown"),
            
            # Additional fields for compatibility
            "dos_val": 1 if "Flood" in raw_alert.get("attack", "") else 0,
            "ddos_val": 1 if "DDoS" in raw_alert.get("attack", "") else 0,
        }
        
        return compat_alert
    
    # ─────────────────────────────────────────────────────────────────────────
    # COOLDOWN/DEDUPLICATION
    # ─────────────────────────────────────────────────────────────────────────
    
    def _should_alert(self, alert: dict) -> bool:
        """Check if alert should be sent (cooldown deduplication)"""
        
        alert_key = (alert.get("attack"), alert.get("layer"))
        current_time = time.time()
        cooldown = self.config.ALERT_COOLDOWN
        
        # Check if we've alerted on this before
        last_alert_time = self.alert_cache.get(alert_key, 0)
        
        if current_time - last_alert_time < cooldown:
            return False  # Still in cooldown
        
        # Update cache
        self.alert_cache[alert_key] = current_time
        return True
    
    # ─────────────────────────────────────────────────────────────────────────
    # CONFIGURATION
    # ─────────────────────────────────────────────────────────────────────────
    
    def set_confidence_threshold(self, threshold: int):
        """Set minimum confidence threshold for alerts"""
        self.confidence_threshold = max(0, min(100, threshold))
        logger.info(f"[CONFIG] Confidence threshold set to {self.confidence_threshold}%")
    
    def get_statistics(self) -> dict:
        """Get detection statistics"""
        return {
            "total_packets": self.packet_count,
            "total_alerts": sum(self.detection_stats.values()),
            "detection_stats": dict(self.detection_stats),
            "confidence_threshold": self.confidence_threshold,
        }
    
    def get_stats(self) -> dict:
        """Return snapshot of active tracker state for the GUI dashboard (compatibility)"""
        return {
            "total_packets": self.packet_count,
            "total_alerts": sum(self.detection_stats.values()),
        }
    
    def print_statistics(self):
        """Print statistics summary"""
        stats = self.get_statistics()
        
        print("\n" + "="*70)
        print("ADVANCED DETECTION ENGINE - STATISTICS")
        print("="*70)
        print(f"Packets Analyzed: {stats['total_packets']}")
        print(f"Total Alerts: {stats['total_alerts']}")
        
        if stats['total_packets'] > 0:
            detection_rate = (stats['total_alerts'] / stats['total_packets']) * 100
            print(f"Detection Rate: {detection_rate:.2f}%")
        
        print(f"Confidence Threshold: {stats['confidence_threshold']}%")
        
        if stats['detection_stats']:
            print("\nAttacks Detected:")
            for attack, count in sorted(stats['detection_stats'].items(), 
                                       key=lambda x: x[1], reverse=True):
                print(f"  {attack}: {count}")
        
        print("="*70 + "\n")
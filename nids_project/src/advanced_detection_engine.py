#!/usr/bin/env python3
"""
Advanced Signature-Based Detection Engine
==========================================

Features:
- Adaptive signature detection (no manual threshold changes)
- Contextual payload analysis
- DoS/DDoS behavioral signatures
- Attack-specific detection strategies
- Protocol-specific pattern recognition
- Statistical signature matching
- No machine learning - pure signature-based analysis

Author: NIDS Team
Date: 2026-03-27
"""

import re
import json
import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta


class AdvancedSignatureDetector:
    """Advanced signature-based detection with adaptive analysis"""
    
    def __init__(self, rules_file: str = "rules.json"):
        """Initialize advanced detector"""
        self.rules = self._load_rules(rules_file)
        
        # Behavioral tracking (for signature-based anomalies)
        self.packet_history = deque(maxlen=10000)  # Last 10k packets
        self.flow_tracker = defaultdict(lambda: {
            'packets': deque(maxlen=1000),
            'start_time': None,
            'attack_detected': False
        })
        
        # Protocol-specific statistics (for adaptive baselines)
        self.protocol_stats = {
            'tcp_syn': [],      # SYN packet history (rate)
            'tcp_ack': [],      # ACK packet history (rate)
            'tcp_rst': [],      # RST packet history (rate)
            'udp': [],          # UDP packet history (rate)
            'icmp': [],         # ICMP packet history (rate)
        }
        
        # Attack signature cache
        self.attack_signatures = self._build_attack_signatures()
        
        # Detection statistics
        self.detection_stats = defaultdict(int)
    
    def _load_rules(self, rules_file: str) -> List[Dict]:
        """Load rules from JSON file"""
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading rules: {e}")
            return []
    
    def _build_attack_signatures(self) -> Dict:
        """Build attack-specific signature patterns"""
        signatures = {
            'ddos_flood': {
                'description': 'DDoS flood attack signature',
                'patterns': [
                    {
                        'name': 'rate_spike',
                        'detector': self._detect_rate_spike
                    },
                    {
                        'name': 'source_diversity',
                        'detector': self._detect_source_diversity
                    },
                    {
                        'name': 'consistent_target',
                        'detector': self._detect_consistent_target
                    }
                ]
            },
            'payload_injection': {
                'description': 'Payload-based attack signatures',
                'patterns': [
                    {
                        'name': 'sql_patterns',
                        'detector': self._detect_sql_injection_advanced
                    },
                    {
                        'name': 'xss_patterns',
                        'detector': self._detect_xss_advanced
                    },
                    {
                        'name': 'command_patterns',
                        'detector': self._detect_command_injection_advanced
                    },
                    {
                        'name': 'encoding_patterns',
                        'detector': self._detect_encoding_attacks
                    }
                ]
            },
            'port_scan': {
                'description': 'Port scanning signatures',
                'patterns': [
                    {
                        'name': 'syn_scan',
                        'detector': self._detect_syn_scan_signature
                    },
                    {
                        'name': 'stealth_scan',
                        'detector': self._detect_stealth_scan
                    },
                    {
                        'name': 'sequential_pattern',
                        'detector': self._detect_sequential_ports
                    }
                ]
            },
            'brute_force': {
                'description': 'Brute force attack signatures',
                'patterns': [
                    {
                        'name': 'connection_rate',
                        'detector': self._detect_brute_force_rate
                    },
                    {
                        'name': 'failed_auth_pattern',
                        'detector': self._detect_auth_failures
                    },
                    {
                        'name': 'timing_pattern',
                        'detector': self._detect_timing_pattern
                    }
                ]
            }
        }
        return signatures
    
    # ─────────────────────────────────────────────────────────────────────────
    # ADAPTIVE THRESHOLD DETECTION (No manual threshold needed)
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_adaptive_threshold(self, packet_type: str, window_seconds: int = 10) -> int:
        """
        Calculate adaptive threshold based on recent traffic patterns
        
        Algorithm:
        - Analyze last 100 packets of this type
        - Calculate baseline (median rate)
        - Set threshold to baseline * spike_multiplier
        - No fixed thresholds needed
        """
        
        if packet_type not in self.protocol_stats:
            return 50  # Default fallback
        
        history = self.protocol_stats[packet_type]
        
        if len(history) < 10:
            # Not enough data, use defaults
            return self._get_default_threshold(packet_type)
        
        # Get recent rates
        recent_rates = history[-100:]
        
        if not recent_rates:
            return self._get_default_threshold(packet_type)
        
        # Calculate statistics
        median_rate = sorted(recent_rates)[len(recent_rates) // 2]
        max_rate = max(recent_rates)
        min_rate = min(recent_rates)
        
        # Detection threshold = 2x median (adaptive spike detection)
        # or 1.5x if there's high variance
        variance = max_rate - min_rate
        
        if variance > median_rate * 2:
            # High variance = use 1.5x multiplier
            threshold = int(median_rate * 1.5)
        else:
            # Low variance = use 2x multiplier
            threshold = int(median_rate * 2)
        
        # Minimum threshold of 5 packets/10s
        return max(threshold, 5)
    
    def _get_default_threshold(self, packet_type: str) -> int:
        """Get default threshold for packet type"""
        defaults = {
            'tcp_syn': 50,
            'tcp_ack': 40,
            'tcp_rst': 40,
            'udp': 100,
            'icmp': 50,
        }
        return defaults.get(packet_type, 50)
    
    # ─────────────────────────────────────────────────────────────────────────
    # DDoS/FLOOD ATTACK DETECTION (Advanced Signatures)
    # ─────────────────────────────────────────────────────────────────────────
    
    def _detect_rate_spike(self, packet_type: str, current_rate: int) -> Tuple[bool, float]:
        """
        Detect sudden rate spike (signature of DDoS)
        
        Algorithm:
        - Compare current rate to recent average
        - If current > average * threshold_multiplier → DDoS
        - Multiplier adapts based on traffic variance
        """
        
        if packet_type not in self.protocol_stats:
            return False, 0.0
        
        history = self.protocol_stats[packet_type][-100:]
        
        if len(history) < 5:
            return False, 0.0
        
        # Calculate baseline (average of last 100 samples)
        baseline = sum(history) / len(history)
        
        if baseline == 0:
            baseline = 1
        
        # Calculate spike ratio
        spike_ratio = current_rate / baseline
        
        # Threshold multiplier adapts based on variance
        variance = max(history) - min(history)
        
        if variance > baseline:
            # High variance traffic = require higher spike
            threshold_multiplier = 3.0
        else:
            # Normal traffic = lower threshold for detection
            threshold_multiplier = 2.5
        
        # Confidence score (0-100)
        confidence = min(100, (spike_ratio / threshold_multiplier) * 100)
        
        is_spike = spike_ratio > threshold_multiplier
        
        return is_spike, confidence
    
    def _detect_source_diversity(self, target_ip: str, target_port: int) -> Tuple[bool, int, float]:
        """
        Detect attack from multiple sources (multi-source DDoS signature)
        
        Algorithm:
        - Track unique source IPs attacking same target+port
        - If sources > threshold_per_second → DDoS
        - Threshold calculated from baseline
        """
        
        key = (target_ip, target_port)
        unique_sources = set()
        
        # Look at last 1000 packets for this target
        for pkt in self.packet_history:
            if pkt.get('dst_ip') == target_ip and pkt.get('dst_port') == target_port:
                unique_sources.add(pkt['src_ip'])
        
        current_sources = len(unique_sources)
        
        # Signature: >5 unique sources in 10 seconds = DDoS
        # But adaptive: if baseline high, increase threshold
        
        baseline_sources = 0
        if len(self.packet_history) > 100:
            # Calculate baseline unique sources
            baseline_seen = set()
            for pkt in list(self.packet_history)[-100:]:
                if pkt.get('dst_ip') == target_ip and pkt.get('dst_port') == target_port:
                    baseline_seen.add(pkt['src_ip'])
            baseline_sources = len(baseline_seen)
        
        # Threshold: baseline * 2 or 5, whichever is higher
        threshold_sources = max(baseline_sources * 1.5 + 2, 5)
        
        # Confidence: how much over threshold
        confidence = min(100, (current_sources / threshold_sources) * 100)
        
        is_multisource = current_sources > threshold_sources
        
        return is_multisource, current_sources, confidence
    
    def _detect_consistent_target(self, pkt_dict: Dict) -> Tuple[bool, float]:
        """
        Detect attack maintaining consistent target (DDoS signature)
        
        Algorithm:
        - Check if same destination port being hit repeatedly
        - Signature: >70% of packets to same port in 10s window
        - Indicates targeted attack vs random traffic
        """
        
        dst_port = pkt_dict.get('dst_port')
        if not dst_port:
            return False, 0.0
        
        dst_ip = pkt_dict.get('dst_ip')
        key = (dst_ip, dst_port)
        
        # Count packets to this target in last 100 packets
        target_count = 0
        total_count = 0
        
        for pkt in list(self.packet_history)[-100:]:
            if pkt.get('dst_ip') == dst_ip:
                total_count += 1
                if pkt.get('dst_port') == dst_port:
                    target_count += 1
        
        if total_count == 0:
            return False, 0.0
        
        # Calculate concentration
        concentration = target_count / total_count
        
        # Signature: >70% concentrated on one port
        threshold = 0.70
        confidence = min(100, (concentration / threshold) * 100)
        
        is_consistent = concentration > threshold
        
        return is_consistent, confidence
    
    # ─────────────────────────────────────────────────────────────────────────
    # ADVANCED PAYLOAD DETECTION (Context-Aware)
    # ─────────────────────────────────────────────────────────────────────────
    
    def _detect_sql_injection_advanced(self, payload: bytes, context: Dict = None) -> Tuple[bool, float]:
        """
        Advanced SQL injection detection with context awareness
        
        Signatures:
        1. Direct SQL keywords (UNION SELECT, OR 1=1, etc)
        2. SQL functions (SLEEP, BENCHMARK, CHAR, HEX, etc)
        3. Comment sequences (--,  #, /*, etc)
        4. Encoding bypass attempts (hex encoding, unicode, etc)
        5. Stacked queries (;DROP TABLE, etc)
        """
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore').upper()
        except:
            return False, 0.0
        
        # Signature groups with weights
        signatures = {
            'direct_keywords': {
                'weight': 0.25,
                'patterns': [
                    r"UNION\s+SELECT",
                    r"SELECT\s+.*\s+FROM",
                    r"OR\s+'?1'?\s*=\s*'?1'?",
                    r"AND\s+'?1'?\s*=\s*'?1'?",
                    r"DROP\s+TABLE",
                    r"INSERT\s+INTO",
                    r"DELETE\s+FROM",
                    r"UPDATE\s+.*\s+SET",
                ]
            },
            'timing_attacks': {
                'weight': 0.25,
                'patterns': [
                    r"SLEEP\s*\(\s*\d+\s*\)",
                    r"BENCHMARK\s*\(",
                    r"WAITFOR\s+DELAY",
                    r"PG_SLEEP",
                ]
            },
            'function_calls': {
                'weight': 0.20,
                'patterns': [
                    r"CHAR\s*\(",
                    r"HEX\s*\(",
                    r"CONCAT\s*\(",
                    r"SUBSTR\s*\(",
                    r"CAST\s*\(",
                    r"UNHEX\s*\(",
                ]
            },
            'comment_sequences': {
                'weight': 0.15,
                'patterns': [
                    r"--\s*$",
                    r"#\s*$",
                    r"/\*.*\*/",
                ]
            },
            'encoding_bypass': {
                'weight': 0.15,
                'patterns': [
                    r"0x[0-9a-f]{4,}",
                    r"\\x[0-9a-f]{2}",
                    r"CHAR\(.*,.*,.*\)",
                ]
            }
        }
        
        total_score = 0.0
        matches = 0
        
        for group_name, group_data in signatures.items():
            for pattern in group_data['patterns']:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    total_score += group_data['weight']
                    matches += 1
                    break  # Only count once per group
        
        # Confidence: total score out of 1.0 = percentage
        confidence = min(100, total_score * 100)
        
        # Threshold: any match = detected (confidence > 20%)
        is_detected = matches > 0
        
        return is_detected, confidence
    
    def _detect_xss_advanced(self, payload: bytes, context: Dict = None) -> Tuple[bool, float]:
        """
        Advanced XSS detection with context-aware analysis
        
        Signatures:
        1. Script tags and handlers
        2. Event handlers (onerror, onload, etc)
        3. Protocol handlers (javascript:, data:, etc)
        4. DOM-based (innerHTML, eval, etc)
        5. Encoding bypass (unicode, hex, entities)
        """
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
        except:
            return False, 0.0
        
        # Signature groups
        signatures = {
            'script_tags': {
                'weight': 0.30,
                'patterns': [
                    r"<script[^>]*>",
                    r"</script>",
                    r"javascript:",
                ]
            },
            'event_handlers': {
                'weight': 0.30,
                'patterns': [
                    r"onerror\s*=",
                    r"onload\s*=",
                    r"onmouseover\s*=",
                    r"onclick\s*=",
                    r"onkeydown\s*=",
                    r"onmouseenter\s*=",
                    r"onmouseleave\s*=",
                ]
            },
            'protocol_handlers': {
                'weight': 0.25,
                'patterns': [
                    r"data:text/html",
                    r"vbscript:",
                    r"about:blank",
                ]
            },
            'html_entities': {
                'weight': 0.15,
                'patterns': [
                    r"<iframe[^>]*>",
                    r"<embed[^>]*>",
                    r"<object[^>]*>",
                    r"<svg[^>]*>",
                    r"<img[^>]*onerror",
                ]
            },
        }
        
        total_score = 0.0
        matches = 0
        
        for group_name, group_data in signatures.items():
            for pattern in group_data['patterns']:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    total_score += group_data['weight']
                    matches += 1
                    break
        
        confidence = min(100, total_score * 100)
        is_detected = matches > 0
        
        return is_detected, confidence
    
    def _detect_command_injection_advanced(self, payload: bytes, context: Dict = None) -> Tuple[bool, float]:
        """
        Advanced command injection detection with context awareness
        
        Signatures:
        1. Shell metacharacters (|, ;, &&, ||)
        2. Command substitution ($(), backticks)
        3. Dangerous commands (rm, wget, curl, etc)
        4. Path traversal sequences (../, ..\, etc)
        5. Variable expansion (environment vars)
        """
        
        payload_str = payload.decode('utf-8', errors='ignore')
        
        signatures = {
            'metacharacters': {
                'weight': 0.25,
                'patterns': [
                    r"\s*\|\s*",
                    r";\s*[a-zA-Z_]",
                    r"&&\s*[a-zA-Z_]",
                    r"\|\|\s*[a-zA-Z_]",
                    r"&\s*[a-zA-Z_]",
                ]
            },
            'command_substitution': {
                'weight': 0.25,
                'patterns': [
                    r"\$\([^\)]+\)",
                    r"`[^`]+`",
                    r"\$\{[^\}]+\}",
                ]
            },
            'dangerous_commands': {
                'weight': 0.25,
                'patterns': [
                    r"\brm\s+-rf",
                    r"\bwget\s+",
                    r"\bcurl\s+",
                    r"\bcat\s+/",
                    r"\bgit\s+clone",
                    r"\bpython\s+-c",
                    r"\bperl\s+-e",
                    r"\bsh\s+-c",
                    r"\bbash\s+-c",
                ]
            },
            'path_traversal': {
                'weight': 0.15,
                'patterns': [
                    r"\.\./",
                    r"\.\.",
                    r"/etc/passwd",
                    r"/etc/shadow",
                ]
            },
            'variable_expansion': {
                'weight': 0.10,
                'patterns': [
                    r"\$[A-Z_]+",
                    r"\%[A-Z_]+\%",
                ]
            }
        }
        
        total_score = 0.0
        matches = 0
        
        for group_name, group_data in signatures.items():
            for pattern in group_data['patterns']:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    total_score += group_data['weight']
                    matches += 1
                    break
        
        confidence = min(100, total_score * 100)
        is_detected = matches > 0
        
        return is_detected, confidence
    
    def _detect_encoding_attacks(self, payload: bytes, context: Dict = None) -> Tuple[bool, float]:
        """
        Detect encoding bypass attempts in payloads
        
        Signatures:
        1. Hex encoding patterns
        2. Unicode encoding
        3. Base64 encoded suspicious content
        4. Double encoding
        5. Null byte injection
        """
        
        signatures = {
            'hex_encoding': {
                'weight': 0.20,
                'pattern': r"0x[0-9a-f]{6,}",
            },
            'unicode_escape': {
                'weight': 0.20,
                'pattern': r"\\u[0-9a-f]{4}",
            },
            'base64_high': {
                'weight': 0.15,
                'pattern': r"[A-Za-z0-9+/]{20,}={0,2}",
            },
            'null_bytes': {
                'weight': 0.30,
                'pattern': None,  # Special handling
            },
            'double_encoding': {
                'weight': 0.15,
                'pattern': r"%[0-9a-f]{2}%[0-9a-f]{2}",
            }
        }
        
        total_score = 0.0
        matches = 0
        
        payload_str = payload.decode('utf-8', errors='ignore')
        
        for sig_name, sig_data in signatures.items():
            if sig_name == 'null_bytes':
                # Special: check for null bytes
                if b'\x00' in payload:
                    total_score += sig_data['weight']
                    matches += 1
            else:
                if re.search(sig_data['pattern'], payload_str, re.IGNORECASE):
                    total_score += sig_data['weight']
                    matches += 1
        
        confidence = min(100, total_score * 100)
        is_detected = matches > 0
        
        return is_detected, confidence
    
    # ─────────────────────────────────────────────────────────────────────────
    # PORT SCAN DETECTION (Advanced Signatures)
    # ─────────────────────────────────────────────────────────────────────────
    
    def _detect_syn_scan_signature(self, pkt_dict: Dict) -> Tuple[bool, float]:
        """
        Detect TCP SYN scan signature
        
        Behavioral Signatures:
        1. SYN packets to multiple ports from same source
        2. No return traffic (no responses waited for)
        3. Random port sequence
        4. High packet rate to different ports
        5. TTL patterns (often lower than normal)
        """
        
        src_ip = pkt_dict.get('src_ip')
        if not src_ip:
            return False, 0.0
        
        # Look for SYN packets from this source in last 50 packets
        syn_ports = []
        ttl_values = []
        
        for pkt in list(self.packet_history)[-50:]:
            if pkt.get('src_ip') == src_ip and pkt.get('flags') == 'S':
                syn_ports.append(pkt.get('dst_port'))
                ttl_values.append(pkt.get('ttl', 64))
        
        confidence = 0.0
        
        # Signature 1: Multiple different ports
        if len(set(syn_ports)) >= 5:
            confidence += 20  # At least 5 different ports = likely scan
        
        # Signature 2: Quick succession (no wait for response)
        if len(syn_ports) >= 3:
            confidence += 20
        
        # Signature 3: TTL lower than typical (64 or 128)
        if ttl_values:
            avg_ttl = sum(ttl_values) / len(ttl_values)
            if avg_ttl < 60:
                confidence += 15
        
        # Signature 4: Ports not in sequential order (scanning algorithm)
        if len(set(syn_ports)) >= 5:
            # Check if ports are somewhat random
            sorted_ports = sorted(syn_ports)
            diffs = [sorted_ports[i+1] - sorted_ports[i] for i in range(len(sorted_ports)-1)]
            
            if diffs:  # Not strictly sequential
                avg_diff = sum(diffs) / len(diffs)
                if avg_diff > 2:  # Gaps indicate scanning
                    confidence += 15
        
        is_scan = confidence > 30
        
        return is_scan, min(confidence, 100)
    
    def _detect_stealth_scan(self, pkt_dict: Dict) -> Tuple[bool, float]:
        """
        Detect stealth scanning techniques (FIN, NULL, XMAS scans)
        
        Behavioral Signatures:
        1. Unusual flag combinations (FIN-only, NULL flags, FPU flags)
        2. Multiple unusual flags to same/multiple ports
        3. No data payload
        4. Quick succession without responses
        """
        
        src_ip = pkt_dict.get('src_ip')
        flags = pkt_dict.get('flags', '')
        
        # Stealth flags: F (FIN), no flags (NULL), FPU (XMAS)
        stealth_flags = ['F', '', 'FPU', 'FP', 'FU', 'PU']
        
        is_stealth_flag = flags in stealth_flags
        
        if not is_stealth_flag:
            return False, 0.0
        
        confidence = 0.0
        
        # Check for pattern from same source
        unusual_flag_packets = []
        
        for pkt in list(self.packet_history)[-50:]:
            if pkt.get('src_ip') == src_ip:
                pkt_flags = pkt.get('flags', '')
                if pkt_flags in stealth_flags:
                    unusual_flag_packets.append(pkt)
        
        if len(unusual_flag_packets) >= 3:
            confidence += 30
        
        # Check for multiple ports
        if len(set(p.get('dst_port') for p in unusual_flag_packets)) >= 3:
            confidence += 20
        
        # Check for empty payload
        payloads = [p.get('payload', b'') for p in unusual_flag_packets]
        if all(len(p) == 0 for p in payloads):
            confidence += 15
        
        is_stealth = confidence > 30
        
        return is_stealth, min(confidence, 100)
    
    def _detect_sequential_ports(self, pkt_dict: Dict) -> Tuple[bool, float]:
        """
        Detect sequential/organized port scanning
        
        Algorithm:
        - Looking for ports being scanned in order or pattern
        - Signature of automated scanner
        """
        
        src_ip = pkt_dict.get('src_ip')
        
        # Get recent ports from this source
        dst_ports = []
        
        for pkt in list(self.packet_history)[-30:]:
            if pkt.get('src_ip') == src_ip:
                dst_ports.append(pkt.get('dst_port'))
        
        if len(dst_ports) < 5:
            return False, 0.0
        
        # Check for patterns
        confidence = 0.0
        
        # Sequential check
        sorted_ports = sorted(dst_ports)
        diffs = [sorted_ports[i+1] - sorted_ports[i] for i in range(len(sorted_ports)-1)]
        
        # If differences are small and consistent, likely sequential scan
        if diffs and max(diffs) <= 10:
            confidence += 35
        
        # Check for known port patterns (common scans)
        well_known_ports = {22, 80, 443, 3306, 5432, 27017, 6379, 8080, 8443, 9200}
        if set(dst_ports) & well_known_ports:
            confidence += 20
        
        is_sequential = confidence > 30
        
        return is_sequential, min(confidence, 100)
    
    # ─────────────────────────────────────────────────────────────────────────
    # BRUTE FORCE ATTACK DETECTION (Advanced Signatures)
    # ─────────────────────────────────────────────────────────────────────────
    
    def _detect_brute_force_rate(self, pkt_dict: Dict, service_port: int) -> Tuple[bool, float]:
        """
        Detect brute force by high connection rate
        
        Algorithm:
        - Track connection attempts per source
        - Adaptive threshold: baseline * 3
        - Signature: rapid connection attempts with resets
        """
        
        src_ip = pkt_dict.get('src_ip')
        dst_port = pkt_dict.get('dst_port', service_port)
        
        # Count recent connection attempts
        connections = []
        
        for pkt in list(self.packet_history)[-100:]:
            if pkt.get('src_ip') == src_ip and pkt.get('dst_port') == dst_port:
                if pkt.get('flags') in ['S', 'PA']:  # SYN or PUSH-ACK
                    connections.append(pkt.get('timestamp', time.time()))
        
        if len(connections) < 3:
            return False, 0.0
        
        # Calculate rate per second
        if len(connections) > 0:
            time_span = connections[-1] - connections[0]
            if time_span == 0:
                time_span = 1
            
            rate = len(connections) / time_span
        else:
            return False, 0.0
        
        # Baseline rate (from history)
        baseline_rate = 2.0  # 2 connections/second baseline
        
        # Threshold: baseline * 3
        threshold_rate = baseline_rate * 3
        
        # Confidence
        confidence = min(100, (rate / threshold_rate) * 100)
        
        is_brute_force = rate > threshold_rate
        
        return is_brute_force, confidence
    
    def _detect_auth_failures(self, pkt_dict: Dict) -> Tuple[bool, float]:
        """
        Detect repeat failed authentication attempts
        
        Signatures:
        - Multiple TCP resets/refusals from same source
        - Same port, repeated attempts
        - Failed connection signatures
        """
        
        src_ip = pkt_dict.get('src_ip')
        dst_port = pkt_dict.get('dst_port')
        
        # Count RST flags (failed connections)
        failed_attempts = []
        
        for pkt in list(self.packet_history)[-50:]:
            if (pkt.get('src_ip') == src_ip and 
                pkt.get('dst_port') == dst_port and
                pkt.get('flags') == 'R'):  # RST = reset/reject
                failed_attempts.append(pkt)
        
        confidence = 0.0
        
        # Signature: multiple RST packets
        if len(failed_attempts) >= 5:
            confidence += 40
        
        if len(failed_attempts) >= 10:
            confidence += 30
        
        is_failed_auth = confidence > 40
        
        return is_failed_auth, confidence
    
    def _detect_timing_pattern(self, pkt_dict: Dict) -> Tuple[bool, float]:
        """
        Detect timing patterns in brute force
        
        Algorithm:
        - Rapid repeated attempts = automated tool
        - Regular intervals = structured attack
        """
        
        src_ip = pkt_dict.get('src_ip')
        dst_port = pkt_dict.get('dst_port')
        
        # Get timestamps of recent packets from this source to this port
        timestamps = []
        
        for pkt in list(self.packet_history)[-50:]:
            if (pkt.get('src_ip') == src_ip and 
                pkt.get('dst_port') == dst_port):
                timestamps.append(pkt.get('timestamp', time.time()))
        
        if len(timestamps) < 5:
            return False, 0.0
        
        # Calculate intervals between attempts
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        confidence = 0.0
        
        # Very tight intervals (<0.5 sec) = automated
        tight_intervals = [i for i in intervals if i < 0.5]
        if len(tight_intervals) > len(intervals) * 0.5:
            confidence += 40
        
        # Very regular intervals (std dev < 0.1) = structured
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            if std_dev < 0.1 and avg_interval < 2:
                confidence += 30
        
        is_pattern = confidence > 30
        
        return is_pattern, confidence
    
    # ─────────────────────────────────────────────────────────────────────────
    # MAIN DETECTION INTERFACE
    # ─────────────────────────────────────────────────────────────────────────
    
    def detect_attack(self, pkt_dict: Dict) -> List[Dict]:
        """
        Advanced signature-based attack detection
        
        Returns list of detected attacks with confidence scores
        """
        
        alerts = []
        
        # Add to history
        pkt_dict['timestamp'] = time.time()
        self.packet_history.append(pkt_dict)
        
        # Layer 1: Signature matching on headers
        layer1_alerts = self._detect_signature_attacks(pkt_dict)
        alerts.extend(layer1_alerts)
        
        # Layer 2: Advanced payload analysis
        if pkt_dict.get('payload'):
            layer2_alerts = self._detect_payload_attacks(pkt_dict)
            alerts.extend(layer2_alerts)
        
        # Layer 3: Behavioral/DDoS patterns
        layer3_alerts = self._detect_behavioral_attacks(pkt_dict)
        alerts.extend(layer3_alerts)
        
        return alerts
    
    def _detect_signature_attacks(self, pkt_dict: Dict) -> List[Dict]:
        """Detect attacks using signature-based rules"""
        alerts = []
        
        protocol = pkt_dict.get('protocol')
        flags = pkt_dict.get('flags')
        dst_port = pkt_dict.get('dst_port')
        
        # Advanced detections based on protocol
        if protocol == 6:  # TCP
            # SYN scan detection
            if flags == 'S':
                is_scan, conf = self._detect_syn_scan_signature(pkt_dict)
                if is_scan:
                    alerts.append({
                        'attack': 'TCP SYN Port Scan',
                        'severity': 'MEDIUM',
                        'layer': 'Signature',
                        'confidence': conf
                    })
            
            # Stealth scan detection
            elif flags in ['F', '', 'FPU']:
                is_stealth, conf = self._detect_stealth_scan(pkt_dict)
                if is_stealth:
                    alerts.append({
                        'attack': 'Stealth Port Scan',
                        'severity': 'MEDIUM',
                        'layer': 'Signature',
                        'confidence': conf
                    })
        
        return alerts
    
    def _detect_payload_attacks(self, pkt_dict: Dict) -> List[Dict]:
        """Detect payload-based injection attacks"""
        alerts = []
        
        payload = pkt_dict.get('payload', b'')
        
        # SQL Injection
        is_sql, conf = self._detect_sql_injection_advanced(payload)
        if is_sql:
            alerts.append({
                'attack': 'SQL Injection Attack',
                'severity': 'CRITICAL',
                'layer': 'Payload',
                'confidence': conf
            })
        
        # XSS
        is_xss, conf = self._detect_xss_advanced(payload)
        if is_xss:
            alerts.append({
                'attack': 'Cross-Site Scripting (XSS)',
                'severity': 'HIGH',
                'layer': 'Payload',
                'confidence': conf
            })
        
        # Command Injection
        is_cmd, conf = self._detect_command_injection_advanced(payload)
        if is_cmd:
            alerts.append({
                'attack': 'Command Injection Attack',
                'severity': 'CRITICAL',
                'layer': 'Payload',
                'confidence': conf
            })
        
        # Encoding attacks
        is_enc, conf = self._detect_encoding_attacks(payload)
        if is_enc:
            alerts.append({
                'attack': 'Encoding Attack',
                'severity': 'MEDIUM',
                'layer': 'Payload',
                'confidence': conf
            })
        
        return alerts
    
    def _detect_behavioral_attacks(self, pkt_dict: Dict) -> List[Dict]:
        """Detect behavioral/DDoS attacks"""
        alerts = []
        
        protocol = pkt_dict.get('protocol')
        flags = pkt_dict.get('flags', '')
        
        # Track packet type for rate calculation
        packet_type = None
        if protocol == 6:  # TCP
            if flags == 'S':
                packet_type = 'tcp_syn'
            elif flags == 'A':
                packet_type = 'tcp_ack'
            elif flags == 'R':
                packet_type = 'tcp_rst'
        elif protocol == 17:
            packet_type = 'udp'
        elif protocol == 1:
            packet_type = 'icmp'
        
        # Calculate rate
        if packet_type:
            rate = self._calculate_rate(packet_type)
            if rate > 0:
                self.protocol_stats[packet_type].append(rate)
            
            # Check for rate spike
            is_spike, conf = self._detect_rate_spike(packet_type, rate)
            if is_spike:
                alerts.append({
                    'attack': f'{packet_type.upper()} Flood',
                    'severity': 'HIGH',
                    'layer': 'Behavioral',
                    'confidence': conf
                })
        
        # Multi-source DDoS detection
        is_multi, sources, conf = self._detect_source_diversity(
            pkt_dict.get('dst_ip'),
            pkt_dict.get('dst_port')
        )
        if is_multi:
            alerts.append({
                'attack': 'DDoS Multi-Source Attack',
                'severity': 'CRITICAL',
                'layer': 'Behavioral',
                'confidence': conf,
                'sources': sources
            })
        
        # Consistent target detection
        is_consistent, conf = self._detect_consistent_target(pkt_dict)
        if is_consistent:
            alerts.append({
                'attack': 'Targeted Attack Pattern',
                'severity': 'HIGH',
                'layer': 'Behavioral',
                'confidence': conf
            })
        
        return alerts
    
    def _calculate_rate(self, packet_type: str) -> int:
        """Calculate packet rate per second"""
        if not self.packet_history:
            return 0
        
        current_time = time.time()
        time_window = 1.0  # 1 second window
        
        count = 0
        for pkt in list(self.packet_history)[-100:]:
            if current_time - pkt.get('timestamp', current_time) <= time_window:
                # Match packet type
                protocol = pkt.get('protocol')
                flags = pkt.get('flags', '')
                
                if packet_type == 'tcp_syn' and protocol == 6 and flags == 'S':
                    count += 1
                elif packet_type == 'tcp_ack' and protocol == 6 and flags == 'A':
                    count += 1
                elif packet_type == 'tcp_rst' and protocol == 6 and flags == 'R':
                    count += 1
                elif packet_type == 'udp' and protocol == 17:
                    count += 1
                elif packet_type == 'icmp' and protocol == 1:
                    count += 1
        
        return count
    
    def print_stats(self):
        """Print detection statistics"""
        print("\n" + "="*70)
        print("ADVANCED DETECTION STATISTICS")
        print("="*70)
        print(f"Total packets analyzed: {len(self.packet_history)}")
        print(f"Total alerts generated: {sum(self.detection_stats.values())}")
        print("\nAttacks detected:")
        for attack, count in sorted(self.detection_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {attack}: {count}")
        print("="*70 + "\n")


# Example usage
if __name__ == "__main__":
    detector = AdvancedSignatureDetector()
    
    # Example packet
    test_packet = {
        'src_ip': '192.168.1.50',
        'dst_ip': '192.168.1.100',
        'protocol': 6,
        'src_port': 54325,
        'dst_port': 80,
        'flags': 'PA',
        'payload': b"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1",
    }
    
    alerts = detector.detect_attack(test_packet)
    
    if alerts:
        print("\n[ALERTS DETECTED]")
        for alert in alerts:
            print(f"  {alert['attack']} - Confidence: {alert['confidence']:.1f}%")
    else:
        print("No threats detected")

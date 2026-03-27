#!/usr/bin/env python3
"""
ALERT MANAGER - Centralized Alert Routing with Rate Limiting
============================================================

Features:
- Multi-channel alert routing (GUI, Discord, Log, Gemini)
- Rate limiting for Discord (10 alerts/hour) and Gemini (5 analyses/hour)
- Alert deduplication and batching
- Instantaneous logging to file
- Real-time GUI updates
- Severity-based routing

Author: Advanced NIDS Team
Date: March 27, 2026
"""

import logging
import threading
import queue
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Callable
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger("AlertManager")


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertChannel(Enum):
    """Alert delivery channels"""
    GUI = "gui"
    DISCORD = "discord"
    LOG = "log"
    GEMINI = "gemini"


class RateLimitConfig:
    """Rate limiting configuration"""
    
    def __init__(self):
        self.discord_limit = 10      # Alerts per hour
        self.gemini_limit = 5        # Analyses per hour
        self.gemini_severity_filter = ["CRITICAL", "HIGH"]  # Only for these
        self.log_all = True          # Log all alerts
        self.gui_all = True          # Show all in GUI


class AlertManager:
    """
    Centralized alert manager with channel-specific formatting,
    rate limiting, and deduplication.
    """
    
    def __init__(self, gui_callback: Optional[Callable] = None):
        """
        Initialize alert manager.
        
        Args:
            gui_callback: Function to call for GUI alerts (signature: func(alert_dict))
        """
        self.gui_callback = gui_callback
        self.config = RateLimitConfig()
        
        # Rate limiting
        self.discord_timestamps = []
        self.gemini_timestamps = []
        self.lock = threading.Lock()
        
        # Alert queue and worker thread
        self.alert_queue = queue.Queue(maxsize=1000)
        self.running = True
        self.worker_thread = threading.Thread(target=self._alert_worker, daemon=True)
        self.worker_thread.start()
        
        # Alert history for deduplication
        self.recent_alerts = defaultdict(list)
        self.max_history = 100  # Keep last 100 alerts
        
        # Statistics
        self.stats = {
            'total_alerts': 0,
            'discord_sent': 0,
            'gemini_analyses': 0,
            'log_entries': 0,
            'gui_alerts': 0,
        }
        
        # Log file initialization
        self._init_log_file()
        
        logger.info("[ALERT MANAGER] Initialized")
    
    def _init_log_file(self):
        """Initialize alert log file"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.log_filepath = f"alerts_{timestamp}.log"
            
            with open(self.log_filepath, 'w') as f:
                f.write("╔" + "═"*96 + "╗\n")
                f.write("║" + " " * 20 + "NIDS ALERT LOG" + " " * 63 + "║\n")
                f.write("║" + f" {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + " " * 79 + "║\n")
                f.write("╚" + "═"*96 + "╝\n\n")
                
            logger.info(f"[LOG] Alert log file: {self.log_filepath}")
        except Exception as e:
            logger.error(f"[LOG INIT] Error: {e}")
    
    def submit_alert(self, alert: Dict):
        """
        Submit alert for processing.
        
        Args:
            alert: Alert dictionary with keys like:
                - type: Attack type
                - severity: Severity level
                - src, dst: Source and destination IPs
                - recommendations: List of recommended actions
                - timestamp: Alert timestamp
        """
        try:
            self.alert_queue.put_nowait(alert)
        except queue.Full:
            logger.warning("[QUEUE] Alert queue full, dropping alert")
    
    def _alert_worker(self):
        """Background worker thread for alert processing"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=0.5)
                self._process_alert(alert)
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"[WORKER] Error: {e}")
    
    def _process_alert(self, alert: Dict):
        """Process alert and route to appropriate channels"""
        try:
            with self.lock:
                self.stats['total_alerts'] += 1
            
            severity = alert.get('severity', 'MEDIUM')
            
            # Check for deduplication
            if self._is_duplicate(alert):
                logger.debug(f"[DUP] Skipping duplicate alert: {alert.get('type')}")
                return
            
            # Route to channels
            self._send_to_log(alert)
            self._send_to_gui(alert)
            
            # Rate-limited channels
            if severity in ['CRITICAL', 'HIGH']:
                if self._can_send_discord():
                    self._send_to_discord(alert)
                else:
                    logger.info("[RATE LIMIT] Discord rate limit exceeded")
                
                if self._can_run_gemini_analysis():
                    self._run_gemini_analysis(alert)
                else:
                    logger.info("[RATE LIMIT] Gemini rate limit exceeded")
            
            # Add to history
            self._add_to_history(alert)
        
        except Exception as e:
            logger.error(f"[PROCESS] Error processing alert: {e}")
    
    # ────────────────────────────────────────────────────────────────────────
    # CHANNEL IMPLEMENTATIONS
    # ────────────────────────────────────────────────────────────────────────
    
    def _send_to_log(self, alert: Dict):
        """Send alert to log file (instantaneous)"""
        try:
            timestamp = datetime.fromtimestamp(alert.get('timestamp', time.time()))
            
            log_line = (
                f"\n[{timestamp.strftime('%H:%M:%S')}] "
                f"{alert.get('severity', 'MEDIUM'):>8} | "
                f"{alert.get('type', 'Unknown'):30} | "
                f"{alert.get('src', 'Unknown'):15} → {alert.get('dst', 'Unknown'):15} | "
                f"Confidence: {alert.get('confidence', 0):.0f}%"
            )
            
            # Append to log file
            with open(self.log_filepath, 'a') as f:
                f.write(log_line + '\n')
                
                # Add recommendations if critical/high
                if alert.get('severity') in ['CRITICAL', 'HIGH']:
                    f.write("  Actions:\n")
                    for rec in alert.get('recommendations', [])[:3]:
                        f.write(f"    • {rec}\n")
            
            with self.lock:
                self.stats['log_entries'] += 1
            
            logger.debug(f"[LOG] Alert logged: {alert.get('type')}")
        
        except Exception as e:
            logger.error(f"[LOG ERROR] {e}")
    
    def _send_to_gui(self, alert: Dict):
        """Send alert to GUI (real-time update)"""
        try:
            if self.gui_callback:
                # Format for GUI
                gui_alert = {
                    'timestamp': datetime.fromtimestamp(
                        alert.get('timestamp', time.time())
                    ).strftime('%H:%M:%S'),
                    'type': alert.get('type', 'Unknown'),
                    'severity': alert.get('severity', 'MEDIUM'),
                    'src': alert.get('src', 'Unknown'),
                    'dst': alert.get('dst', 'Unknown'),
                    'src_port': alert.get('src_port', 0),
                    'dst_port': alert.get('dst_port', 0),
                    'confidence': alert.get('confidence', 0),
                    'recommendation': alert.get('recommendations', ['N/A'])[0],
                }
                
                # Call GUI callback
                self.gui_callback(gui_alert)
                
                with self.lock:
                    self.stats['gui_alerts'] += 1
                
                logger.debug(f"[GUI] Alert sent: {alert.get('type')}")
        
        except Exception as e:
            logger.error(f"[GUI ERROR] {e}")
    
    def _send_to_discord(self, alert: Dict) -> bool:
        """Send formatted alert to Discord (rate-limited)"""
        try:
            if not self._can_send_discord():
                return False
            
            severity_emoji = {
                'CRITICAL': '🚨',
                'HIGH': '🔴',
                'MEDIUM': '🟠',
                'LOW': '⚠️',
            }.get(alert.get('severity', 'MEDIUM'), '⚠️')
            
            # Format Discord message
            discord_payload = {
                'content': (
                    f"{severity_emoji} **{alert.get('type', 'Unknown')}** "
                    f"[{alert.get('severity')}]\n"
                    f"**From:** `{alert.get('src', 'Unknown')}:{alert.get('src_port', 0)}`\n"
                    f"**To:** `{alert.get('dst', 'Unknown')}:{alert.get('dst_port', 0)}`\n"
                    f"**Confidence:** {alert.get('confidence', 0):.0f}%\n"
                    f"**Action:** {alert.get('recommendations', ['N/A'])[0]}"
                ),
                'timestamp': datetime.now().isoformat(),
            }
            
            # In production, send to Discord webhook
            # For now, just log it
            logger.info(
                f"[DISCORD] Would send: {alert.get('type')} "
                f"from {alert.get('src')} to {alert.get('dst')}"
            )
            
            # Record rate limit
            with self.lock:
                self.discord_timestamps.append(datetime.now())
                self.stats['discord_sent'] += 1
            
            return True
        
        except Exception as e:
            logger.error(f"[DISCORD ERROR] {e}")
            return False
    
    def _run_gemini_analysis(self, alert: Dict) -> bool:
        """Run AI analysis using Gemini (rate-limited, critical/high only)"""
        try:
            if not self._can_run_gemini_analysis():
                return False
            
            # Check severity filter
            if alert.get('severity') not in self.config.gemini_severity_filter:
                return False
            
            # Build analysis prompt
            analysis_context = f"""
Analyze this security alert and provide brief assessment:

Attack Type: {alert.get('type')}
Severity: {alert.get('severity')}
Confidence: {alert.get('confidence', 0):.0f}%
Source IP: {alert.get('src')}
Target IP: {alert.get('dst')}
Port: {alert.get('dst_port')}

Provide:
1. Attack analysis (2-3 sentences)
2. Immediate risk assessment
3. Top 2 remediation steps
"""
            
            # In production, call Gemini API
            logger.info(f"[GEMINI] Would analyze: {alert.get('type')}")
            
            # Record rate limit
            with self.lock:
                self.gemini_timestamps.append(datetime.now())
                self.stats['gemini_analyses'] += 1
            
            return True
        
        except Exception as e:
            logger.error(f"[GEMINI ERROR] {e}")
            return False
    
    # ────────────────────────────────────────────────────────────────────────
    # RATE LIMITING
    # ────────────────────────────────────────────────────────────────────────
    
    def _can_send_discord(self) -> bool:
        """Check if Discord alert can be sent (rate limit check)"""
        with self.lock:
            now = datetime.now()
            one_hour_ago = now - timedelta(hours=1)
            
            # Remove timestamps outside window
            self.discord_timestamps = [
                ts for ts in self.discord_timestamps if ts > one_hour_ago
            ]
            
            return len(self.discord_timestamps) < self.config.discord_limit
    
    def _can_run_gemini_analysis(self) -> bool:
        """Check if Gemini analysis can run (rate limit check)"""
        with self.lock:
            now = datetime.now()
            one_hour_ago = now - timedelta(hours=1)
            
            # Remove timestamps outside window
            self.gemini_timestamps = [
                ts for ts in self.gemini_timestamps if ts > one_hour_ago
            ]
            
            return len(self.gemini_timestamps) < self.config.gemini_limit
    
    # ────────────────────────────────────────────────────────────────────────
    # DEDUPLICATION & HISTORY
    # ────────────────────────────────────────────────────────────────────────
    
    def _is_duplicate(self, alert: Dict, window: int = 60) -> bool:
        """Check if alert is duplicate (within time window)"""
        try:
            alert_key = (
                alert.get('type'),
                alert.get('src'),
                alert.get('dst'),
                alert.get('dst_port')
            )
            
            now = time.time()
            window_start = now - window
            
            # Check recent alerts
            recent = [
                a for a in self.recent_alerts[alert_key]
                if a > window_start
            ]
            
            return len(recent) > 0
        
        except Exception as e:
            logger.error(f"[DUP CHECK] Error: {e}")
            return False
    
    def _add_to_history(self, alert: Dict):
        """Add alert to history for deduplication"""
        try:
            alert_key = (
                alert.get('type'),
                alert.get('src'),
                alert.get('dst'),
                alert.get('dst_port')
            )
            
            self.recent_alerts[alert_key].append(time.time())
            
            # Keep only recent entries
            if len(self.recent_alerts[alert_key]) > self.max_history:
                self.recent_alerts[alert_key] = self.recent_alerts[alert_key][-self.max_history:]
        
        except Exception as e:
            logger.error(f"[HISTORY] Error: {e}")
    
    # ────────────────────────────────────────────────────────────────────────
    # STATISTICS & REPORTING
    # ────────────────────────────────────────────────────────────────────────
    
    def get_statistics(self) -> Dict:
        """Get alert manager statistics"""
        with self.lock:
            return dict(self.stats)
    
    def get_rate_limit_status(self) -> Dict:
        """Get current rate limit status"""
        with self.lock:
            now = datetime.now()
            one_hour_ago = now - timedelta(hours=1)
            
            discord_recent = len(
                [ts for ts in self.discord_timestamps if ts > one_hour_ago]
            )
            gemini_recent = len(
                [ts for ts in self.gemini_timestamps if ts > one_hour_ago]
            )
            
            return {
                'discord': {
                    'used': discord_recent,
                    'limit': self.config.discord_limit,
                    'remaining': max(0, self.config.discord_limit - discord_recent),
                },
                'gemini': {
                    'used': gemini_recent,
                    'limit': self.config.gemini_limit,
                    'remaining': max(0, self.config.gemini_limit - gemini_recent),
                },
            }
    
    def shutdown(self):
        """Shutdown alert manager"""
        self.running = False
        self.worker_thread.join(timeout=5)
        logger.info("[SHUTDOWN] Alert manager shut down")


# Factory function
def create_alert_manager(gui_callback: Optional[Callable] = None) -> AlertManager:
    """Create and return alert manager instance"""
    return AlertManager(gui_callback)

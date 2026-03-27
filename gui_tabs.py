#!/usr/bin/env python3
"""
GUI Tabs for Network Scanner and Hotspot Monitor
==================================================

Provides PyQt6-based tabs that integrate NetworkScanner and 
HotspotMonitor data into the main NIDS dashboard.

Features:
- Real-time device/threat tracking
- Theme-aware styling
- Live threat level indicators
- Device activity monitoring
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QPushButton, QHeaderView, QTabWidget, QPlainTextEdit, QLineEdit,
    QComboBox, QSpinBox, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont
import logging

logger = logging.getLogger("GUITabs")

# ========== COLOR PALETTES ==========
COLORS_DARK = {
    "bg_deep":     "#080c14",
    "bg_panel":    "#0d1220",
    "bg_card":     "#111827",
    "text_primary": "#e0e0e0",
    "text_muted":  "#888",
    "cyan":        "#00d9ff",
    "amber":       "#ffa500",
    "orange":      "#ff7b00",
    "red":         "#ff4444",
    "green":       "#00cc00",
    "border":      "#1a2332",
}

COLORS_LIGHT = {
    "bg_deep":     "#ffffff",
    "bg_panel":    "#f5f5f5",
    "bg_card":     "#eeeeee",
    "text_primary": "#222",
    "text_muted":  "#888",
    "cyan":        "#0088cc",
    "amber":       "#cc6600",
    "orange":      "#ff6600",
    "red":         "#dd0000",
    "green":       "#00aa00",
    "border":      "#cccccc",
}


class NetworkScannerTab(QWidget):
    """
    Network Scanner Tab - LAN Threat Detection & Network Analysis
    
    Features:
    - Device search (IP, CIDR, ranges, partial)
    - Advanced port scanning
    - Vulnerability detection
    """
    
    def __init__(self):
        super().__init__()
        self.scanner = None
        self.colors = COLORS_DARK
        self._setup_ui()
        self._scanning = False
    
    def _setup_ui(self):
        """Setup comprehensive scanner UI"""
        main_lay = QVBoxLayout(self)
        main_lay.setContentsMargins(10, 10, 10, 10)
        main_lay.setSpacing(10)
        
        # ====== TITLE ======
        title = QLabel("🔍 NETWORK SCANNER - Advanced LAN Analysis")
        title.setFont(QFont("Courier", 10, QFont.Weight.Bold))
        title.setStyleSheet(f"color: #00d9ff;")
        main_lay.addWidget(title)
        
        # ====== SEARCH & SCAN CONTROLS ======
        controls_lay = QHBoxLayout()
        
        # Discover button
        self.discover_btn = QPushButton("🔍 Discover")
        self.discover_btn.setMaximumWidth(100)
        self.discover_btn.clicked.connect(self._on_discover_clicked)
        controls_lay.addWidget(self.discover_btn)
        
        # Search input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search: IP, IP range (192.168.1.1-50), CIDR (192.168.1.0/24)...")
        self.search_input.setMaximumHeight(32)
        controls_lay.addWidget(QLabel("Search:"), 0)
        controls_lay.addWidget(self.search_input, 1)
        
        # Search button
        self.search_btn = QPushButton("Search Devices")
        self.search_btn.setMaximumWidth(120)
        self.search_btn.clicked.connect(self._on_search_clicked)
        controls_lay.addWidget(self.search_btn)
        
        # Scan type selector
        self.scan_type = QComboBox()
        self.scan_type.addItems(["Ports", "Vulnerabilities", "Full Scan"])
        controls_lay.addWidget(QLabel("Scan:"), 0)
        controls_lay.addWidget(self.scan_type)
        
        # Scan button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setMaximumWidth(100)
        self.scan_btn.clicked.connect(self._on_scan_clicked)
        controls_lay.addWidget(self.scan_btn)
        
        main_lay.addLayout(controls_lay)
        
        # ====== PROGRESS BAR ======
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumHeight(20)
        main_lay.addWidget(self.progress_bar)
        
        # ====== RESULTS TABS ======
        self.results_tabs = QTabWidget()
        
        # Tab 1: Devices
        self.devices_table = QTableWidget(0, 6)
        self.devices_table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Threat Level", "Packets", "Status", "Action"
        ])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devices_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.devices_table.setAlternatingRowColors(True)
        self.results_tabs.addTab(self.devices_table, "Devices")
        
        # Tab 2: Open Ports
        self.ports_table = QTableWidget(0, 5)
        self.ports_table.setHorizontalHeaderLabels([
            "IP Address", "Port", "Service", "State", "Vulnerability"
        ])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ports_table.setAlternatingRowColors(True)
        self.results_tabs.addTab(self.ports_table, "Open Ports")
        
        # Tab 3: Vulnerabilities
        self.vulns_table = QTableWidget(0, 6)
        self.vulns_table.setHorizontalHeaderLabels([
            "IP Address", "Port", "Service", "CVE ID", "Severity", "Remediation"
        ])
        self.vulns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.vulns_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.vulns_table.setAlternatingRowColors(True)
        self.results_tabs.addTab(self.vulns_table, "Vulnerabilities")
        
        # Tab 4: Details/Logs
        self.logs_text = QPlainTextEdit()
        self.logs_text.setReadOnly(True)
        self.results_tabs.addTab(self.logs_text, "Logs")
        
        main_lay.addWidget(self.results_tabs)
        
        # ====== STATUS BAR ======
        self.status_label = QLabel("Ready | Devices: 0 | Ports: 0 | Vulnerabilities: 0")
        self.status_label.setFont(QFont("Courier", 9))
        self.status_label.setStyleSheet("color: #00d9ff; font-weight: bold;")
        main_lay.addWidget(self.status_label)
        
        self._apply_theme(self.colors)
    
    def set_scanner(self, scanner):
        """Set network scanner instance"""
        self.scanner = scanner
        self._log("Network Scanner initialized")
        self._log("Ready - Click 'Discover' or enter search query to begin scanning")
    
    def _on_search_clicked(self):
        """Handle search button click"""
        if not self.scanner:
            self._log("❌ ERROR: Scanner not initialized")
            return
        
        query = self.search_input.text().strip()
        if not query:
            self._log("❌ ERROR: Enter search query (IP, range, or CIDR)")
            self._log("   Examples: 192.168.1.100  |  192.168.1.0/24  |  192.168.1.1-50")
            return
        
        self._log(f"🔍 Searching for devices matching: {query}")
        
        try:
            results = self.scanner.search_devices(query)
            self._display_search_results(results)
            if results:
                self._log(f"✅ Found {len(results)} device(s)")
            else:
                self._log(f"⚠️  No devices matched '{query}'. Try discovering devices first!")
        except Exception as e:
            self._log(f"❌ ERROR: Search failed - {e}")
    
    def _discover_devices_auto(self):
        """Auto-discover devices on network in background"""
        if not self.scanner:
            return
        
        try:
            self._log("🔄 Auto-discovering devices on network...")
            self._log("   Trying: ARP scan → ICMP ping → DNS lookup...")
            results = self.scanner.discover_devices()
            if results:
                self._display_search_results(results)
                self._log(f"✅ Auto-discovery complete: Found {len(results)} device(s)")
            else:
                self._log("⚠️  No devices discovered. Try clicking 'Discover' button or checking network.")
        except Exception as e:
            self._log(f"ℹ️  Auto-discovery note: {str(e)[:50]}")
    
    def _on_discover_clicked(self):
        """Handle discover button click"""
        if not self.scanner:
            self._log("❌ ERROR: Scanner not initialized")
            return
        
        self._log("🔄 Starting network device discovery scan...")
        self._log("   Trying: ARP scan (requires admin) → ICMP ping → DNS lookup...")
        self.discover_btn.setEnabled(False)
        
        try:
            results = self.scanner.discover_devices()
            if results:
                self._display_search_results(results)
                self._log(f"✅ Discovery complete: Found {len(results)} device(s)")
                self._log(f"   Devices: {', '.join([r['ip'] for r in results])}")
            else:
                self._log("⚠️  No devices found in network scan")
                self._log("   Tips: Run with admin privileges, or manually enter an IP to scan")
        except Exception as e:
            self._log(f"❌ ERROR: Discovery failed - {e}")
        finally:
            self.discover_btn.setEnabled(True)


    
    def _on_scan_clicked(self):
        """Handle scan button click"""
        if not self.scanner:
            self._log("ERROR: Scanner not initialized")
            return
        
        if self._scanning:
            self._log("Scan already in progress...")
            return
        
        scan_type = self.scan_type.currentText()
        search_query = self.search_input.text().strip()
        
        if not search_query:
            self._log("ERROR: Enter target IP or search query first")
            return
        
        self._scanning = True
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        try:
            # Extract target IP from search query (simplified - take first result)
            target_ip = None
            if '/' not in search_query and '-' not in search_query:
                # Single IP
                target_ip = search_query
            else:
                # Get results from search first
                results = self.scanner.search_devices(search_query)
                if results:
                    target_ip = results[0]['ip']
            
            if not target_ip:
                self._log("ERROR: Could not determine target IP")
                self._scanning = False
                self.scan_btn.setEnabled(True)
                self.progress_bar.setVisible(False)
                return
            
            self._log(f"Starting {scan_type} scan on {target_ip}...")
            
            if scan_type == "Ports":
                self._scan_ports(target_ip)
            elif scan_type == "Vulnerabilities":
                self._scan_vulnerabilities(target_ip)
            else:  # Full Scan
                self._scan_ports(target_ip)
                self._scan_vulnerabilities(target_ip)
            
            self.progress_bar.setValue(100)
            self._log(f"{scan_type} scan completed")
            
        except Exception as e:
            self._log(f"ERROR: Scan failed - {e}")
        
        finally:
            self._scanning = False
            self.scan_btn.setEnabled(True)
            self.progress_bar.setVisible(False)
    
    def _scan_ports(self, target_ip: str):
        """Perform port scan"""
        self._log(f"Scanning open ports on {target_ip}...")
        
        try:
            results = self.scanner.scan_ports(target_ip)
            self._display_port_results(results)
        except Exception as e:
            self._log(f"ERROR: Port scan failed - {e}")
    
    def _scan_vulnerabilities(self, target_ip: str):
        """Perform vulnerability scan"""
        self._log(f"Scanning for vulnerabilities on {target_ip}...")
        
        try:
            results = self.scanner.scan_vulnerabilities(target_ip)
            self._display_vuln_results(results)
        except Exception as e:
            self._log(f"ERROR: Vulnerability scan failed - {e}")
    
    def _display_search_results(self, devices: list):
        """Display search results in devices table"""
        self.devices_table.setRowCount(0)
        
        for device in devices:
            row = self.devices_table.rowCount()
            self.devices_table.insertRow(row)
            
            # IP
            ip_item = QTableWidgetItem(device.get('ip', 'N/A'))
            self.devices_table.setItem(row, 0, ip_item)
            
            # MAC
            mac_item = QTableWidgetItem(device.get('mac', 'N/A'))
            self.devices_table.setItem(row, 1, mac_item)
            
            # Threat Level (based on vulnerabilities)
            open_ports = len(device.get('open_ports', []))
            vulns = len(device.get('vulnerabilities', []))
            threat = min(100, (open_ports * 5) + (vulns * 10))  # Simple threat calculation
            threat_item = QTableWidgetItem(f"{threat:.1f}%")
            if threat > 75:
                threat_item.setForeground(QColor("#ff4444"))
            elif threat > 50:
                threat_item.setForeground(QColor("#ffa500"))
            else:
                threat_item.setForeground(QColor("#00cc00"))
            self.devices_table.setItem(row, 2, threat_item)
            
            # Hostname as activity indicator
            hostname = device.get('hostname', 'unknown')
            self.devices_table.setItem(row, 3, QTableWidgetItem(hostname))
            
            # Status based on vulnerabilities
            if vulns > 0:
                status = "🚨 VULNERABLE" if threat > 75 else "⚠️  AT RISK"
                status_item = QTableWidgetItem(status)
                status_item.setForeground(QColor("#ff4444" if threat > 75 else "#ffa500"))
            else:
                status = "✓ CLEAN"
                status_item = QTableWidgetItem(status)
                status_item.setForeground(QColor("#00cc00"))
            self.devices_table.setItem(row, 4, status_item)
            
            # Action button (scan ports)
            self.devices_table.setItem(row, 5, QTableWidgetItem(f"Ports: {open_ports}"))
        
        self.results_tabs.setCurrentWidget(self.devices_table)
    
    def _display_port_results(self, results: dict):
        """Display port scan results"""
        self.ports_table.setRowCount(0)
        
        for ip, scan_data in results.items():
            open_ports = scan_data.get('open_ports', [])
            services = scan_data.get('services', {})
            
            for port in open_ports:
                row = self.ports_table.rowCount()
                self.ports_table.insertRow(row)
                
                self.ports_table.setItem(row, 0, QTableWidgetItem(ip))
                self.ports_table.setItem(row, 1, QTableWidgetItem(str(port)))
                
                service = services.get(port, 'unknown')
                self.ports_table.setItem(row, 2, QTableWidgetItem(service))
                self.ports_table.setItem(row, 3, QTableWidgetItem("open"))
                self.ports_table.setItem(row, 4, QTableWidgetItem("--"))
        
        self._log(f"✅ Port scan complete: {self.ports_table.rowCount()} ports found")
        self.results_tabs.setCurrentWidget(self.ports_table)
    
    def _display_vuln_results(self, results: dict):
        """Display vulnerability scan results"""
        self.vulns_table.setRowCount(0)
        
        for ip, vulns_list in results.items():
            for vuln in vulns_list:
                row = self.vulns_table.rowCount()
                self.vulns_table.insertRow(row)
                
                self.vulns_table.setItem(row, 0, QTableWidgetItem(ip))
                self.vulns_table.setItem(row, 1, QTableWidgetItem(vuln.get('name', 'Unknown')))
                self.vulns_table.setItem(row, 2, QTableWidgetItem(vuln.get('description', 'N/A')[:40]))
                
                cve = vuln.get('cve', 'N/A')
                cve_item = QTableWidgetItem(cve)
                self.vulns_table.setItem(row, 3, cve_item)
                
                severity = vuln.get('severity', 'MEDIUM')
                severity_item = QTableWidgetItem(severity)
                if severity == "CRITICAL":
                    severity_item.setForeground(QColor("#ff4444"))
                elif severity == "HIGH":
                    severity_item.setForeground(QColor("#ffa500"))
                elif severity == "MEDIUM":
                    severity_item.setForeground(QColor("#ffff00"))
                self.vulns_table.setItem(row, 4, severity_item)
                
                remediation = vuln.get('remediation', 'Manual review')[:50]
                self.vulns_table.setItem(row, 5, QTableWidgetItem(remediation))
        
        self._log(f"✅ Vulnerability scan complete: {self.vulns_table.rowCount()} vulnerabilities found")
        self.results_tabs.setCurrentWidget(self.vulns_table)
    
    def _log(self, message: str):
        """Add message to logs"""
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs_text.appendPlainText(f"[{ts}] {message}")
        
        # Update status
        device_count = self.devices_table.rowCount()
        port_count = self.ports_table.rowCount()
        vuln_count = self.vulns_table.rowCount()
        self.status_label.setText(
            f"Ready | Devices: {device_count} | Ports: {port_count} | Vulnerabilities: {vuln_count}"
        )
    
    def _apply_theme(self, colors):
        """Apply theme colors to all elements"""
        # Table styling
        table_style = f"""
            QTableWidget {{
                background-color: {colors['bg_deep']};
                color: {colors['text_primary']};
                gridline-color: {colors['border']};
                border: 1px solid {colors['border']};
            }}
            QTableWidget::item {{
                padding: 4px;
                border: none;
            }}
            QHeaderView::section {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                padding: 4px;
                border: none;
                font-weight: bold;
            }}
        """
        
        self.devices_table.setStyleSheet(table_style)
        self.ports_table.setStyleSheet(table_style)
        self.vulns_table.setStyleSheet(table_style)
        
        # Text edit styling
        self.logs_text.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {colors['bg_deep']};
                color: {colors['text_primary']};
                border: 1px solid {colors['border']};
                font-family: Courier;
                font-size: 9pt;
            }}
        """)
        
        # Input styling
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                border: 1px solid {colors['border']};
                padding: 4px;
            }}
        """)
        
        # Button styling
        btn_style = f"""
            QPushButton {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                border: 1px solid {colors['cyan']};
                padding: 4px 8px;
                border-radius: 3px;
            }}
            QPushButton:hover {{
                background-color: {colors['cyan']};
                color: {colors['bg_deep']};
            }}
        """
        self.discover_btn.setStyleSheet(btn_style)
        self.search_btn.setStyleSheet(btn_style)
        self.scan_btn.setStyleSheet(btn_style)
        
        # Combo box styling
        self.scan_type.setStyleSheet(f"""
            QComboBox {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                border: 1px solid {colors['border']};
                padding: 4px;
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox::down-arrow {{
                color: {colors['cyan']};
            }}
        """)
        
        self.setStyleSheet(f"background-color: {colors['bg_panel']};")
    
    def apply_theme(self, colors: dict):
        """Public method to apply theme"""
        self.colors = colors
        self._apply_theme(colors)


class HotspotMonitorTab(QWidget):
    """
    Hotspot Monitor Tab - Connected Device Tracking & Attack Detection
    
    Features:
    - Search connected devices (auto-scan whole hotspot if no input)
    - Attack tracking (to/from connected devices)
    - Real-time attack counters (rule hits, payload hits)
    - Alert system for suspicious activity
    - Device threat scoring
    - Connection statistics
    """
    
    def __init__(self):
        super().__init__()
        self.monitor = None
        self.colors = COLORS_DARK
        self.update_timer = None
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup comprehensive hotspot monitor UI"""
        main_lay = QVBoxLayout(self)
        main_lay.setContentsMargins(10, 10, 10, 10)
        main_lay.setSpacing(10)
        
        # ====== TITLE ======
        title = QLabel("📡 HOTSPOT MONITOR - Connected Device & Attack Tracking")
        title.setFont(QFont("Courier", 10, QFont.Weight.Bold))
        title.setStyleSheet(f"color: #00d9ff;")
        main_lay.addWidget(title)
        
        # ====== SEARCH & SCAN CONTROLS ======
        controls_lay = QHBoxLayout()
        
        # Scan hotspot button
        self.scan_hotspot_btn = QPushButton("📡 Scan Hotspot")
        self.scan_hotspot_btn.setMaximumWidth(120)
        self.scan_hotspot_btn.clicked.connect(self._on_scan_hotspot_clicked)
        controls_lay.addWidget(self.scan_hotspot_btn)
        
        # Search input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search device by MAC, IP, or hostname (leave empty to scan all)...")
        self.search_input.setMaximumHeight(32)
        controls_lay.addWidget(QLabel("Search:"), 0)
        controls_lay.addWidget(self.search_input, 1)
        
        # Search button
        self.search_btn = QPushButton("Search Device")
        self.search_btn.setMaximumWidth(120)
        self.search_btn.clicked.connect(self._on_search_clicked)
        controls_lay.addWidget(self.search_btn)
        
        # Attack filter
        self.attack_filter = QComboBox()
        self.attack_filter.addItems(["All Devices", "Suspicious Only", "High Threat"])
        self.attack_filter.currentTextChanged.connect(self._refresh_devices_table)
        controls_lay.addWidget(QLabel("Filter:"), 0)
        controls_lay.addWidget(self.attack_filter)
        
        main_lay.addLayout(controls_lay)
        
        # ====== RESULTS TABS ======
        self.results_tabs = QTabWidget()
        
        # ===== TAB 1: CONNECTED DEVICES =====
        self.devices_table = QTableWidget(0, 7)
        self.devices_table.setHorizontalHeaderLabels([
            "Device IP", "MAC Address", "Hostname", "Threat Level", 
            "Attacks From", "Attacks To", "Connection Time"
        ])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devices_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.devices_table.setAlternatingRowColors(True)
        self.devices_table.setMaximumHeight(250)
        self.results_tabs.addTab(self.devices_table, "📱 Connected Devices")
        
        # ===== TAB 2: ATTACKS FROM DEVICES =====
        self.attacks_from_table = QTableWidget(0, 6)
        self.attacks_from_table.setHorizontalHeaderLabels([
            "Device", "Attack Type", "Target IP", "Target Port", "Confidence", "Timestamp"
        ])
        self.attacks_from_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.attacks_from_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.attacks_from_table.setAlternatingRowColors(True)
        self.results_tabs.addTab(self.attacks_from_table, "🚀 Attacks FROM Devices")
        
        # ===== TAB 3: ATTACKS TO DEVICES =====
        self.attacks_to_table = QTableWidget(0, 6)
        self.attacks_to_table.setHorizontalHeaderLabels([
            "Device", "Attack Type", "Source IP", "Source Port", "Confidence", "Timestamp"
        ])
        self.attacks_to_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.attacks_to_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.attacks_to_table.setAlternatingRowColors(True)
        self.results_tabs.addTab(self.attacks_to_table, "🎯 Attacks TO Devices")
        
        # ===== TAB 4: ATTACK COUNTERS & STATISTICS =====
        stats_widget = QWidget()
        stats_lay = QVBoxLayout(stats_widget)
        
        # Stats grid
        stats_grid_lay = QHBoxLayout()
        
        # Total attacks counter
        counter1_lay = QVBoxLayout()
        self.total_attacks_label = QLabel("0")
        self.total_attacks_label.setFont(QFont("Courier", 16, QFont.Weight.Bold))
        self.total_attacks_label.setStyleSheet("color: #ff4444;")
        counter1_title = QLabel("Total Attacks Detected")
        counter1_title.setFont(QFont("Courier", 9))
        counter1_lay.addWidget(self.total_attacks_label)
        counter1_lay.addWidget(counter1_title)
        stats_grid_lay.addLayout(counter1_lay)
        
        # Rule hits counter
        counter2_lay = QVBoxLayout()
        self.rule_hits_label = QLabel("0")
        self.rule_hits_label.setFont(QFont("Courier", 16, QFont.Weight.Bold))
        self.rule_hits_label.setStyleSheet("color: #ffa500;")
        counter2_title = QLabel("Rule Hits")
        counter2_title.setFont(QFont("Courier", 9))
        counter2_lay.addWidget(self.rule_hits_label)
        counter2_lay.addWidget(counter2_title)
        stats_grid_lay.addLayout(counter2_lay)
        
        # Payload hits counter
        counter3_lay = QVBoxLayout()
        self.payload_hits_label = QLabel("0")
        self.payload_hits_label.setFont(QFont("Courier", 16, QFont.Weight.Bold))
        self.payload_hits_label.setStyleSheet("color: #ff7b00;")
        counter3_title = QLabel("Payload Hits")
        counter3_title.setFont(QFont("Courier", 9))
        counter3_lay.addWidget(self.payload_hits_label)
        counter3_lay.addWidget(counter3_title)
        stats_grid_lay.addLayout(counter3_lay)
        
        # Suspicious devices counter
        counter4_lay = QVBoxLayout()
        self.suspicious_devices_label = QLabel("0")
        self.suspicious_devices_label.setFont(QFont("Courier", 16, QFont.Weight.Bold))
        self.suspicious_devices_label.setStyleSheet("color: #ff0000;")
        counter4_title = QLabel("Suspicious Devices")
        counter4_title.setFont(QFont("Courier", 9))
        counter4_lay.addWidget(self.suspicious_devices_label)
        counter4_lay.addWidget(counter4_title)
        stats_grid_lay.addLayout(counter4_lay)
        
        stats_lay.addLayout(stats_grid_lay)
        
        # Detailed attack breakdown
        breakdown_label = QLabel("📊 Attack Breakdown by Type")
        breakdown_label.setFont(QFont("Courier", 9, QFont.Weight.Bold))
        breakdown_label.setStyleSheet("color: #00d9ff;")
        stats_lay.addWidget(breakdown_label)
        
        self.attack_breakdown_text = QPlainTextEdit()
        self.attack_breakdown_text.setReadOnly(True)
        self.attack_breakdown_text.setMaximumHeight(300)
        stats_lay.addWidget(self.attack_breakdown_text)
        
        self.results_tabs.addTab(stats_widget, "📊 Attack Statistics")
        
        # ===== TAB 5: ALERTS LOG =====
        self.alerts_text = QPlainTextEdit()
        self.alerts_text.setReadOnly(True)
        self.results_tabs.addTab(self.alerts_text, "⚠️  Alerts & Logs")
        
        main_lay.addWidget(self.results_tabs)
        
        # ====== STATUS BAR ======
        status_lay = QHBoxLayout()
        self.status_label = QLabel("Ready | Devices: 0 | Active Threats: 0")
        self.status_label.setFont(QFont("Courier", 9))
        self.status_label.setStyleSheet("color: #00d9ff; font-weight: bold;")
        status_lay.addWidget(self.status_label)
        
        # Auto-refresh toggle
        self.auto_refresh_checkbox = QPushButton("🔄 Auto-Refresh: OFF")
        self.auto_refresh_checkbox.setMaximumWidth(140)
        self.auto_refresh_checkbox.setCheckable(True)
        self.auto_refresh_checkbox.toggled.connect(self._on_auto_refresh_toggled)
        status_lay.addWidget(self.auto_refresh_checkbox)
        
        main_lay.addLayout(status_lay)
        
        self._apply_theme(self.colors)
        
        # Setup update timer for auto-refresh
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._refresh_all)
    
    def set_monitor(self, monitor):
        """Set hotspot monitor instance"""
        self.monitor = monitor
        self._log("📡 Hotspot Monitor initialized")
        self._log("Ready - Click 'Scan Hotspot' or enter device info to begin monitoring")
    
    def _on_scan_hotspot_clicked(self):
        """Scan entire hotspot for connected devices"""
        if not self.monitor:
            self._log("❌ ERROR: Monitor not initialized")
            return
        
        self._log("🔄 Scanning connected devices on hotspot...")
        
        try:
            # Get all active clients
            clients = self.monitor.get_active_clients()
            
            if clients:
                self._display_devices(clients)
                self._log(f"✅ Found {len(clients)} connected device(s)")
            else:
                self._log("ℹ️  No connected devices found")
                self._display_devices([])
        
        except Exception as e:
            self._log(f"❌ ERROR: Scan failed - {e}")
    
    def _on_search_clicked(self):
        """Search for specific device"""
        if not self.monitor:
            self._log("❌ ERROR: Monitor not initialized")
            return
        
        query = self.search_input.text().strip().lower()
        
        if not query:
            # If empty, scan all devices
            self._on_scan_hotspot_clicked()
            return
        
        self._log(f"🔍 Searching for device: {query}")
        
        try:
            all_clients = self.monitor.get_all_clients()
            results = []
            
            for mac, client in all_clients.items():
                # Search by MAC, IP, or hostname
                if (query in mac.lower() or 
                    (client.ip and query in client.ip.lower()) or
                    (query in client.hostname.lower())):
                    results.append(client.to_dict())
            
            if results:
                self._display_devices(results)
                self._log(f"✅ Found {len(results)} matching device(s)")
            else:
                self._log(f"⚠️  No devices matched '{query}'")
                self._display_devices([])
        
        except Exception as e:
            self._log(f"❌ ERROR: Search failed - {e}")
    
    def _refresh_devices_table(self):
        """Refresh devices table based on filter"""
        if not self.monitor:
            return
        
        filter_type = self.attack_filter.currentText()
        
        if filter_type == "All Devices":
            clients = self.monitor.get_all_clients()
        elif filter_type == "Suspicious Only":
            clients_dict = self.monitor.get_suspicious_clients()
            clients = {c.get('mac'): c for c in clients_dict}
        else:  # High Threat
            clients_dict = self.monitor.get_suspicious_clients()
            clients = {c.get('mac'): c for c in clients_dict if c.get('threat_level', 0) > 50}
        
        # Convert to display format
        display_clients = []
        for mac, client in (clients.items() if isinstance(clients, dict) else [(None, c) for c in clients]):
            if isinstance(client, dict):
                display_clients.append(client)
        
        self._display_devices(display_clients)
    
    def _display_devices(self, devices: list):
        """Display connected devices in table"""
        self.devices_table.setRowCount(0)
        
        for device in devices:
            row = self.devices_table.rowCount()
            self.devices_table.insertRow(row)
            
            # IP
            ip_item = QTableWidgetItem(device.get('ip', 'unknown'))
            self.devices_table.setItem(row, 0, ip_item)
            
            # MAC
            mac_item = QTableWidgetItem(device.get('mac', 'unknown'))
            self.devices_table.setItem(row, 1, mac_item)
            
            # Hostname
            hostname_item = QTableWidgetItem(device.get('hostname', 'unknown'))
            self.devices_table.setItem(row, 2, hostname_item)
            
            # Threat Level
            threat = device.get('threat_level', 0)
            threat_item = QTableWidgetItem(f"{threat:.1f}%")
            if threat > 75:
                threat_item.setForeground(QColor("#ff4444"))
            elif threat > 50:
                threat_item.setForeground(QColor("#ffa500"))
            elif threat > 25:
                threat_item.setForeground(QColor("#ffff00"))
            else:
                threat_item.setForeground(QColor("#00cc00"))
            self.devices_table.setItem(row, 3, threat_item)
            
            # Attacks From
            attacks_from = device.get('attacks_from_device', 0)
            attacks_from_item = QTableWidgetItem(str(attacks_from))
            if attacks_from > 0:
                attacks_from_item.setForeground(QColor("#ff7b00"))
            self.devices_table.setItem(row, 4, attacks_from_item)
            
            # Attacks To
            attacks_to = device.get('attacks_to_device', 0)
            attacks_to_item = QTableWidgetItem(str(attacks_to))
            if attacks_to > 0:
                attacks_to_item.setForeground(QColor("#00d9ff"))
            self.devices_table.setItem(row, 5, attacks_to_item)
            
            # Connection Time
            conn_time = device.get('session_duration', 'unknown')
            self.devices_table.setItem(row, 6, QTableWidgetItem(conn_time))
        
        self._update_attacks_tables()
        self._update_statistics()
        self._update_status()
    
    def _update_attacks_tables(self):
        """Update attacks from/to tables"""
        if not self.monitor:
            return
        
        self.attacks_from_table.setRowCount(0)
        self.attacks_to_table.setRowCount(0)
        
        all_clients = self.monitor.get_all_clients()
        
        for mac, client in all_clients.items():
            # Attacks FROM device
            for attack in client.attacks_from_device:
                row = self.attacks_from_table.rowCount()
                self.attacks_from_table.insertRow(row)
                
                self.attacks_from_table.setItem(row, 0, QTableWidgetItem(client.hostname))
                self.attacks_from_table.setItem(row, 1, QTableWidgetItem(attack.get('type', 'unknown')))
                self.attacks_from_table.setItem(row, 2, QTableWidgetItem(attack.get('target_ip', 'unknown')))
                self.attacks_from_table.setItem(row, 3, QTableWidgetItem(str(attack.get('target_port', '-'))))
                
                confidence = attack.get('confidence', 0)
                conf_item = QTableWidgetItem(f"{confidence:.1f}%")
                if confidence > 75:
                    conf_item.setForeground(QColor("#ff4444"))
                elif confidence > 50:
                    conf_item.setForeground(QColor("#ffa500"))
                self.attacks_from_table.setItem(row, 4, conf_item)
                
                ts = attack.get('timestamp', '')[-8:]  # Last 8 chars (HH:MM:SS)
                self.attacks_from_table.setItem(row, 5, QTableWidgetItem(ts))
            
            # Attacks TO device
            for attack in client.attacks_to_device:
                row = self.attacks_to_table.rowCount()
                self.attacks_to_table.insertRow(row)
                
                self.attacks_to_table.setItem(row, 0, QTableWidgetItem(client.hostname))
                self.attacks_to_table.setItem(row, 1, QTableWidgetItem(attack.get('type', 'unknown')))
                self.attacks_to_table.setItem(row, 2, QTableWidgetItem(attack.get('source_ip', 'unknown')))
                self.attacks_to_table.setItem(row, 3, QTableWidgetItem(str(attack.get('source_port', '-'))))
                
                confidence = attack.get('confidence', 0)
                conf_item = QTableWidgetItem(f"{confidence:.1f}%")
                if confidence > 75:
                    conf_item.setForeground(QColor("#ff4444"))
                elif confidence > 50:
                    conf_item.setForeground(QColor("#ffa500"))
                self.attacks_to_table.setItem(row, 4, conf_item)
                
                ts = attack.get('timestamp', '')[-8:]
                self.attacks_to_table.setItem(row, 5, QTableWidgetItem(ts))
    
    def _update_statistics(self):
        """Update attack statistics"""
        if not self.monitor:
            return
        
        try:
            # Get all clients
            all_clients = self.monitor.get_all_clients()
            
            # Calculate counters
            total_attacks = 0
            rule_hits = 0
            payload_hits = 0
            suspicious_devices = 0
            attack_types = {}
            
            for mac, client in all_clients.items():
                # Count attacks
                attacks_from = len(client.attacks_from_device)
                attacks_to = len(client.attacks_to_device)
                total_attacks += attacks_from + attacks_to
                
                # Count suspicious devices
                if attacks_from > 0 or attacks_to > 0 or client.threat_level > 0:
                    suspicious_devices += 1
                
                # Count attacks by type and gather breakdown
                for attack in client.attacks_from_device + client.attacks_to_device:
                    attack_type = attack.get('type', 'Unknown')
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                    
                    # Simple heuristic: if confidence > 70, count as rule hit
                    if attack.get('confidence', 0) > 70:
                        rule_hits += 1
                    # If low confidence but detected, likely payload pattern match
                    elif attack.get('confidence', 0) > 30:
                        payload_hits += 1
            
            # Update labels
            self.total_attacks_label.setText(str(total_attacks))
            self.rule_hits_label.setText(str(rule_hits))
            self.payload_hits_label.setText(str(payload_hits))
            self.suspicious_devices_label.setText(str(suspicious_devices))
            
            # Update breakdown
            breakdown_text = "Attack Type Breakdown:\n" + "="*50 + "\n"
            for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_attacks * 100) if total_attacks > 0 else 0
                breakdown_text += f"  {attack_type:<20} : {count:>3} attacks ({percentage:>5.1f}%)\n"
            
            if not attack_types:
                breakdown_text += "  (No attacks detected yet)\n"
            
            self.attack_breakdown_text.setPlainText(breakdown_text)
        
        except Exception as e:
            self._log(f"❌ ERROR updating statistics: {e}")
    
    def _on_auto_refresh_toggled(self, checked):
        """Toggle auto-refresh"""
        if checked:
            self.auto_refresh_checkbox.setText("🔄 Auto-Refresh: ON")
            self.auto_refresh_checkbox.setStyleSheet("background-color: #004d00; color: #00cc00;")
            self.update_timer.start(3000)  # Update every 3 seconds
            self._log("🔄 Auto-refresh enabled (3 second interval)")
        else:
            self.auto_refresh_checkbox.setText("🔄 Auto-Refresh: OFF")
            self.auto_refresh_checkbox.setStyleSheet("")
            self.update_timer.stop()
            self._log("🔄 Auto-refresh disabled")
    
    def _refresh_all(self):
        """Refresh all data"""
        try:
            self._refresh_devices_table()
        except Exception as e:
            pass  # Silent update
    
    def _update_status(self):
        """Update status bar"""
        if not self.monitor:
            return
        
        device_count = len(self.monitor.get_all_clients())
        suspicious_count = len(self.monitor.get_suspicious_clients())
        alert_count = self.monitor.total_alerts
        
        self.status_label.setText(
            f"📡 Devices: {device_count} | 🚨 Threats: {suspicious_count} | ⚠️  Alerts: {alert_count}"
        )
    
    def _log(self, message: str):
        """Add message to alerts log"""
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        
        # Add to alerts
        self.alerts_text.appendPlainText(f"[{ts}] {message}")
        
        # Keep only last 1000 lines
        doc = self.alerts_text.document()
        if doc.blockCount() > 1000:
            cursor = self.alerts_text.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.select(cursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
    
    def _apply_theme(self, colors):
        """Apply theme colors"""
        # Table styling
        table_style = f"""
            QTableWidget {{
                background-color: {colors['bg_deep']};
                color: {colors['text_primary']};
                gridline-color: {colors['border']};
                border: 1px solid {colors['border']};
            }}
            QTableWidget::item {{
                padding: 4px;
            }}
            QHeaderView::section {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                padding: 4px;
                border: none;
                font-weight: bold;
            }}
        """
        
        self.devices_table.setStyleSheet(table_style)
        self.attacks_from_table.setStyleSheet(table_style)
        self.attacks_to_table.setStyleSheet(table_style)
        
        # Text edit styling
        text_style = f"""
            QPlainTextEdit {{
                background-color: {colors['bg_deep']};
                color: {colors['text_primary']};
                border: 1px solid {colors['border']};
                font-family: Courier;
                font-size: 9pt;
            }}
        """
        self.alerts_text.setStyleSheet(text_style)
        self.attack_breakdown_text.setStyleSheet(text_style)
        
        # Input styling
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                border: 1px solid {colors['border']};
                padding: 4px;
            }}
        """)
        
        # Button styling
        btn_style = f"""
            QPushButton {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                border: 1px solid {colors['cyan']};
                padding: 4px 8px;
                border-radius: 3px;
            }}
            QPushButton:hover {{
                background-color: {colors['cyan']};
                color: {colors['bg_deep']};
            }}
        """
        self.scan_hotspot_btn.setStyleSheet(btn_style)
        self.search_btn.setStyleSheet(btn_style)
        
        # Combo box
        self.attack_filter.setStyleSheet(f"""
            QComboBox {{
                background-color: {colors['bg_card']};
                color: {colors['text_primary']};
                border: 1px solid {colors['border']};
                padding: 4px;
            }}
        """)
        
        self.setStyleSheet(f"background-color: {colors['bg_panel']};")
    
    def apply_theme(self, colors: dict):
        """Public method to apply theme"""
        self.colors = colors
        self._apply_theme(colors)

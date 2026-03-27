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
    """Hotspot Monitor Tab - To be implemented"""
    def __init__(self):
        super().__init__()
    
    def set_monitor(self, monitor):
        pass
    
    def apply_theme(self, colors):
        pass

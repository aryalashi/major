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
    QLabel, QPushButton, QHeaderView, QTabWidget, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont


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
    Tab widget for Network Scanner display.
    Shows connected devices, threats, and network statistics.
    """
    
    def __init__(self):
        super().__init__()
        self.scanner = None
        self.colors = COLORS_DARK
        self._setup_ui()
        self._update_timer = QTimer()
        self._update_timer.timeout.connect(self._refresh_data)
        self._update_timer.setSingleShot(False)
        # Start timer with longer interval to prevent blocking
        self._update_timer.start(3000)  # Update every 3 seconds
    
    def _setup_ui(self):
        """Setup tab UI"""
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)
        
        # Title
        title = QLabel("NETWORK SCANNER - LAN Threat Detection")
        title.setFont(QFont("Courier", 10, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {self.colors['cyan']};")
        lay.addWidget(title)
        
        # Device table
        self.device_table = QTableWidget(0, 6)
        self.device_table.setHorizontalHeaderLabels([
            "IP Address", "MAC", "Packets", "Threat Level", "Status", "Alerts"
        ])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.device_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.device_table.setAlternatingRowColors(True)
        lay.addWidget(self.device_table)
        
        # Stats label
        self.stats_label = QLabel("Network: Ready | Devices: 0 | Threats: 0 | Packets: 0")
        self.stats_label.setFont(QFont("Courier", 9))
        lay.addWidget(self.stats_label)
        
        self._apply_theme(self.colors)
    
    def set_scanner(self, scanner):
        """Set network scanner instance"""
        self.scanner = scanner
    
    def _refresh_data(self):
        """Refresh data from scanner"""
        if not self.scanner:
            return
        
        try:
            stats = self.scanner.get_network_stats()
            devices = stats.get('devices', {})
            
            # Update device table
            self.device_table.setRowCount(0)
            for ip, device_data in devices.items():
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                
                ip_item = QTableWidgetItem(str(ip))
                mac_item = QTableWidgetItem(str(device_data.get('mac', 'N/A')))
                packets_item = QTableWidgetItem(
                    str(device_data.get('packets_sent', 0) + device_data.get('packets_received', 0))
                )
                threat_item = QTableWidgetItem(f"{device_data.get('threat_level', 0):.1f}%")
                status_item = QTableWidgetItem(
                    "🔴 THREAT" if device_data.get('threat_level', 0) > 50 else "🟢 CLEAN"
                )
                alerts_item = QTableWidgetItem(str(device_data.get('alerts_count', 0)))
                
                # Color code threat level
                if device_data.get('threat_level', 0) > 75:
                    threat_color = self.colors['red']
                elif device_data.get('threat_level', 0) > 50:
                    threat_color = self.colors['orange']
                else:
                    threat_color = self.colors['green']
                
                threat_item.setForeground(QColor(threat_color))
                
                self.device_table.setItem(row, 0, ip_item)
                self.device_table.setItem(row, 1, mac_item)
                self.device_table.setItem(row, 2, packets_item)
                self.device_table.setItem(row, 3, threat_item)
                self.device_table.setItem(row, 4, status_item)
                self.device_table.setItem(row, 5, alerts_item)
            
            # Update stats
            threat_count = sum(1 for d in devices.values() if d.get('threat_level', 0) > 0)
            total_packets = sum(
                d.get('packets_sent', 0) + d.get('packets_received', 0) 
                for d in devices.values()
            )
            
            self.stats_label.setText(
                f"Network: {stats.get('local_network', 'N/A')} | "
                f"Devices: {len(devices)} | "
                f"Threats: {threat_count} | "
                f"Packets: {total_packets}"
            )
        except Exception as e:
            self.stats_label.setText(f"Error: {str(e)[:50]}")
    
    def apply_theme(self, colors: dict):
        """Apply theme colors"""
        self.colors = colors
        self._apply_theme(colors)
    
    def _apply_theme(self, colors):
        """Apply colors to UI elements"""
        self.device_table.setStyleSheet(f"""
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
        """)
        
        self.stats_label.setStyleSheet(f"color: {colors['cyan']}; font-weight: bold;")
        self.setStyleSheet(f"background-color: {colors['bg_panel']};")


class HotspotMonitorTab(QWidget):
    """
    Tab widget for Hotspot Monitor display.
    Shows connected devices, attacks, and data usage.
    """
    
    def __init__(self):
        super().__init__()
        self.monitor = None
        self.colors = COLORS_DARK
        self._setup_ui()
        self._update_timer = QTimer()
        self._update_timer.timeout.connect(self._refresh_data)
        self._update_timer.start(2000)  # Update every 2 seconds
    
    def _setup_ui(self):
        """Setup tab UI"""
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)
        
        # Title
        title = QLabel("HOTSPOT MONITOR - Connected Devices & Threats")
        title.setFont(QFont("Courier", 10, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {self.colors['cyan']};")
        lay.addWidget(title)
        
        # Devices table
        self.device_table = QTableWidget(0, 7)
        self.device_table.setHorizontalHeaderLabels([
            "Hostname", "MAC", "IP", "Data Used", "Threat Level", 
            "Status", "Alerts"
        ])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.device_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.device_table.setAlternatingRowColors(True)
        lay.addWidget(self.device_table)
        
        # Stats label
        self.stats_label = QLabel("Hotspot: Ready | Active: 0 | Suspicious: 0 | Blocked: 0")
        self.stats_label.setFont(QFont("Courier", 9))
        lay.addWidget(self.stats_label)
        
        self._apply_theme(self.colors)
    
    def set_monitor(self, monitor):
        """Set hotspot monitor instance"""
        self.monitor = monitor
    
    def _refresh_data(self):
        """Refresh data from monitor"""
        if not self.monitor:
            return
        
        try:
            stats = self.monitor.get_statistics()
            clients = stats.get('clients', {})
            
            # Update device table
            self.device_table.setRowCount(0)
            for mac, client_data in clients.items():
                if not client_data.get('is_active', False):
                    continue
                
                row = self.device_table.rowCount()
                self.device_table.insertRow(row)
                
                hostname_item = QTableWidgetItem(str(client_data.get('hostname', 'Unknown')))
                mac_item = QTableWidgetItem(str(mac))
                ip_item = QTableWidgetItem(str(client_data.get('ip', 'N/A')))
                data_item = QTableWidgetItem(str(client_data.get('data_usage', '0 B')))
                threat_item = QTableWidgetItem(f"{client_data.get('threat_level', 0):.1f}%")
                
                status = "🚨 THREAT" if client_data.get('threat_level', 0) > 50 else "✓ SAFE"
                status_item = QTableWidgetItem(status)
                
                alerts_item = QTableWidgetItem(str(client_data.get('total_attacks', 0)))
                
                # Color code threat level
                if client_data.get('threat_level', 0) > 75:
                    threat_color = self.colors['red']
                elif client_data.get('threat_level', 0) > 50:
                    threat_color = self.colors['orange']
                else:
                    threat_color = self.colors['green']
                
                threat_item.setForeground(QColor(threat_color))
                
                self.device_table.setItem(row, 0, hostname_item)
                self.device_table.setItem(row, 1, mac_item)
                self.device_table.setItem(row, 2, ip_item)
                self.device_table.setItem(row, 3, data_item)
                self.device_table.setItem(row, 4, threat_item)
                self.device_table.setItem(row, 5, status_item)
                self.device_table.setItem(row, 6, alerts_item)
            
            # Update stats
            suspicious = sum(1 for d in clients.values() if d.get('threat_level', 0) > 0)
            
            self.stats_label.setText(
                f"Hotspot: {stats.get('hotspot_ip', 'N/A')} | "
                f"Active: {stats.get('active_clients', 0)} | "
                f"Suspicious: {suspicious} | "
                f"Blocked: {stats.get('blocked_clients', 0)}"
            )
        except Exception as e:
            self.stats_label.setText(f"Error: {str(e)[:50]}")
    
    def apply_theme(self, colors: dict):
        """Apply theme colors"""
        self.colors = colors
        self._apply_theme(colors)
    
    def _apply_theme(self, colors):
        """Apply colors to UI elements"""
        self.device_table.setStyleSheet(f"""
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
        """)
        
        self.stats_label.setStyleSheet(f"color: {colors['cyan']}; font-weight: bold;")
        self.setStyleSheet(f"background-color: {colors['bg_panel']};")

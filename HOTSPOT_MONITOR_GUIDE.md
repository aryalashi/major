# 📡 Hotspot Monitor - User Guide

## Overview

The **Hotspot Monitor Tab** is a comprehensive device and attack tracking system for your PC's hotspot/shared network. It monitors all connected devices, tracks attacks (both incoming and outgoing), and provides real-time threat alerts.

## Features

### 1. 🔍 **Connected Device Search & Scanning**
- **Auto-Scan Hotspot**: Click "📡 Scan Hotspot" to discover all connected devices
- **Search Device**: Find specific devices by:
  - MAC Address (e.g., `aa:bb:cc:dd:ee:ff`)
  - IP Address (e.g., `192.168.1.100`)
  - Hostname (e.g., `iPhone`, `laptop`)
  - Leave search empty and click "Search Device" to list all connected devices

### 2. 🚀 **Attack Tracking (FROM Devices)**
Monitors attacks originating FROM your connected devices:
- **Attack Type**: Identifies the threat type (DoS, payload injection, malware, etc.)
- **Target IP**: The external destination being attacked
- **Target Port**: Port being targeted
- **Confidence**: How certain the detection is (0-100%)
- **Timestamp**: When the attack was detected

### 3. 🎯 **Attack Tracking (TO Devices)**
Monitors attacks targeting your connected devices:
- **Attack Type**: Type of incoming attack
- **Source IP**: Where the attack came from
- **Source Port**: Source port of the attack
- **Confidence**: Detection confidence level
- **Timestamp**: Detection time

### 4. 📊 **Attack Statistics & Counters**

#### Real-time Counters:
- **Total Attacks Detected**: Cumulative count of all attacks
- **Rule Hits**: Attacks matching known signatures/rules
- **Payload Hits**: Attacks detected via payload pattern matching
- **Suspicious Devices**: Number of devices with detected threats

#### Attack Breakdown:
Detailed breakdown showing:
- Attack type distribution
- Count per attack type
- Percentage of total attacks

### 5. ⚠️ **Alert & Log System**
- Real-time alerts for suspicious activity
- Timestamped log entries for all events
- Automatic log rotation (keeps last 1000 entries)

### 6. 🔄 **Auto-Refresh**
- Toggle auto-refresh mode: Updates every 3 seconds
- Useful for continuous monitoring
- Click "🔄 Auto-Refresh: OFF" to toggle on/off

### 7. 📱 **Device Filtering**
Filter devices by activity level:
- **All Devices**: Show every connected device
- **Suspicious Only**: Show only devices with detected attacks
- **High Threat**: Show only devices with threat level > 50%

## Tab Organization

### 📱 Connected Devices Tab
Shows all connected devices with:
- Device IP address
- MAC address
- Hostname
- Threat Level (color-coded 🟢 green to 🔴 red)
- Attack count (FROM device)
- Attack count (TO device)
- Connection duration

### 🚀 Attacks FROM Devices Tab
Lists all attacks originating from connected devices
- Which device launched the attack
- Attack classification
- Target information
- Confidence score
- Exact timestamp

### 🎯 Attacks TO Devices Tab
Lists all attacks targeting connected devices
- Which device was targeted
- Attack type
- Source of attack
- Confidence level
- Timestamp

### 📊 Attack Statistics Tab
Visual overview of all attack metrics:
- Large counter displays for quick assessment
- Attack type breakdown with percentages
- Percentage of each attack type

### ⚠️ Alerts & Logs Tab
Complete event log with:
- All system events
- Status updates
- Error messages
- Scroll through history

## How to Use

### Scenario 1: Monitor All Connected Devices
1. Click "📡 Scan Hotspot" button
2. Device list appears in the "📱 Connected Devices" tab
3. Review threat levels for each device
4. Switch to "🚀 Attacks FROM Devices" and "🎯 Attacks TO Devices" tabs to see attack history

### Scenario 2: Track Suspicious Device
1. In the search box, enter device MAC, IP, or hostname
2. Click "Search Device"
3. Review the device's threat level and attack counts
4. Check "🚀 Attacks FROM Devices" to see what this device attacked
5. Check "🎯 Attacks TO Devices" to see what attacked this device

### Scenario 3: Find High-Threat Devices Quickly
1. Set the filter to "High Threat"
2. Only devices with threat level > 50% appear
3. Review their associated attacks

### Scenario 4: Monitor Real-Time Activity
1. Click "🔄 Auto-Refresh: OFF" to enable auto-refresh
2. The tab updates every 3 seconds automatically
3. Watch attack counters increase in real-time
4. Click again to disable auto-refresh when not needed

## Threat Level Indicators

### Color Coding:
- 🟢 **Green** (0-25%): Clean device, no threats detected
- 🟡 **Yellow** (25-50%): Minor attacks detected, low concern
- 🟠 **Orange** (50-75%): Multiple attacks, moderate concern
- 🔴 **Red** (75-100%): Serious threats detected, high risk

### Threat Calculation:
```
Threat Level = (Number of Attacks) × 10 + (Attack Confidence Average)
```

## Attack Confidence Levels

- **90-100%**: High confidence - likely real attack
- **70-89%**: Medium-high confidence - probable threat
- **50-69%**: Medium confidence - potential threat
- **30-49%**: Low confidence - suspicious pattern
- **< 30%**: Very low confidence - anomaly detected

## Filtering Options

### Attack Filter Dropdown:
1. **All Devices**: 
   - Shows every connected device
   - Shows all attack records
   - Useful for comprehensive review

2. **Suspicious Only**: 
   - Shows only devices with detected attacks
   - Filters out clean devices
   - Useful for focused threat analysis

3. **High Threat**: 
   - Shows only devices with threat level > 50%
   - Most critical devices only
   - Best for rapid incident response

## Statistics Explained

### Rule Hits
- Attacks matching known malicious signatures
- Attacks with confidence > 70%
- Most reliable threat indicators

### Payload Hits
- Attacks detected via pattern matching in data
- Attacks with confidence between 30-70%
- May include false positives

### Total Attacks
- Sum of rule hits + payload hits + other detections
- Cumulative count

### Suspicious Devices
- Devices with at least one detected attack
- Devices with threat level > 0%

## Tips & Best Practices

### Daily Monitoring:
1. Start each day by scanning the hotspot
2. Review devices connecting for the first time
3. Check the attack statistics tab for trends

### Incident Investigation:
1. Use search to isolate a suspicious device
2. Switch between FROM and TO tabs to understand attack pattern
3. Note the timestamps for correlation with network logs
4. Check confidence scores - high confidence = real threat

### Performance:
- Auto-refresh is useful but uses more CPU
- Disable for large networks (> 50 devices)
- Manual refresh when needed via buttons

### Threat Response:
1. Identify suspicious device via threat level
2. Review attached attacks in both tabs
3. If threat score > 75%, consider:
   - Isolating the device from network
   - Running antivirus/malware scan on device
   - Investigating device's activities

## Data Retention

- **Displayed Data**: Last 3-5 minutes of real-time data
- **Device Memory**: Devices timeout after 5 minutes of no activity
- **Attack Log**: Kept in memory during session
- **Long-term Storage**: Export or log to file as needed

## Troubleshooting

### No Devices Found
- Ensure hotspot is active and devices are connected
- Check network permissions
- Verify ARP scanning is enabled (admin privileges required on Windows)

### Missing Attacks
- Attacks may be filtered by confidence threshold
- Default threshold is 50%
- Low-confidence anomalies may not appear

### Auto-Refresh Not Working
- Check if system CPU is overloaded
- Disable other tabs' auto-refresh
- Check for errors in Alert & Logs tab

### Device Name Shows "Unknown"
- Hostname resolution may fail on some networks
- This is normal - MAC and IP will still be visible

## Integration with Main NIDS

The HotspotMonitor tab integrates with the main NIDS detection engine:
- Uses the same detection rules as NIDS alerts
- Confidence thresholds aligned with main system
- Attack types consistent with alert classification
- Real-time synchronization with detection engine

## Keyboard Shortcuts

- `Ctrl+L`: Clear logs
- `Tab`: Switch between tabs
- `Enter`: Execute search when cursor in search box
- `Space`: Toggle auto-refresh

## Export & Reporting

To capture session data:
1. Manually copy from tabs (select all → copy)
2. Paste into text editor or spreadsheet
3. Consider automation for regular reporting

---

**Version**: 1.0  
**Last Updated**: March 27, 2026  
**Status**: Production Ready

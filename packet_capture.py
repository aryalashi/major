"""
packet_capture.py
-----------------
Packet Capture Engine for NIDS

Captures raw network packets via Scapy and converts them into a canonical,
normalized packet schema before pushing to the detection queue.

Normalization is handled by normalization.py — this module is ONLY
responsible for:
  1. Interface enumeration and selection
  2. Running the Scapy sniff loop
  3. Maintaining a raw-packet evidence buffer for PCAP export
  4. Delegating all field extraction to normalize_packet()

Protocol Classification
-----------------------
Protocol routing is done in normalization.py based on IP.proto field.
This module performs NO direct TCP/UDP/ICMP layer checks — it delegates
entirely to the normalization layer to prevent cross-protocol false positives.

Windows Requirements
--------------------
  Npcap must be installed in WinPcap-compatible mode.
  Application must run as Administrator.
  Download: https://npcap.com
"""

import re
import time
import socket
import logging
import threading
import queue
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger("PacketCapture")

try:
    from scapy.all import sniff, get_if_list, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from normalization import normalize_packet
except ImportError:
    # Allow standalone import without the full project
    normalize_packet = None


# ── Interface Classification Keywords ────────────────────────────────────────

VM_KEYWORDS       = ["virtualbox","vmware","vbox","vmnet","hyper-v",
                     "hyperv","vethernet","docker","wsl","host-only",
                     "nat network","loopback host"]
VPN_KEYWORDS      = ["vpn","tap-windows","nordvpn","expressvpn",
                     "wireguard","openvpn","proton","mullvad",
                     "cisco","anyconnect","globalprotect","tap0"]
WIFI_KEYWORDS     = ["wi-fi","wifi","wireless","wlan","802.11",
                     "airport","wi fi"]
HOTSPOT_KEYWORDS  = ["local area connection*","microsoft wi-fi direct",
                     "hosted network","mobile hotspot","wi-fi direct",
                     "mshostednetwork"]
ETHERNET_KEYWORDS = ["ethernet","local area connection","gigabit",
                     "realtek pcie","intel(r) ethernet","broadcom",
                     "marvell","lan","e1000","e100"]
LOOPBACK_KEYWORDS = ["loopback","npcap loopback"]

TYPE_ICONS = {
    "wifi":     "[WiFi]    ",
    "ethernet": "[Ethernet]",
    "loopback": "[Loopback]",
    "vm":       "[VM]      ",
    "vpn":      "[VPN]     ",
    "hotspot":  "[Hotspot] ",
    "unknown":  "[Unknown] ",
}


# ── Interface Utilities ───────────────────────────────────────────────────────

def _guid_to_name_registry() -> Dict[str, str]:
    """Map Windows NPF GUID → friendly adapter name via Registry."""
    names = {}
    try:
        import winreg
        reg_path = (
            r"SYSTEM\CurrentControlSet\Control\Network"
            r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        )
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(key, i)
                i += 1
                try:
                    conn_key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        rf"{reg_path}\{guid}\Connection"
                    )
                    name, _ = winreg.QueryValueEx(conn_key, "Name")
                    winreg.CloseKey(conn_key)
                    clean = guid.strip("{}")
                    names[clean.upper()] = name
                    names[guid.upper()] = name
                except (FileNotFoundError, OSError):
                    pass
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception as e:
        logger.debug(f"Registry read failed: {e}")
    return names


def _get_all_ips() -> Dict[str, str]:
    """Return {adapter_name_lower: IPv4} for all adapters via ipconfig."""
    ips = {}
    try:
        r = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5
        )
        current = ""
        for line in r.stdout.splitlines():
            if "adapter" in line.lower() and ":" in line:
                m = re.search(r'adapter (.+):', line, re.IGNORECASE)
                if m:
                    current = m.group(1).strip().lower()
            if current and "IPv4 Address" in line:
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    ips[current] = m.group(1)
                    current = ""
    except Exception as e:
        logger.debug(f"ipconfig parse failed: {e}")
    return ips


def _classify(friendly_name: str, ip: str) -> str:
    n = friendly_name.lower()
    if any(k in n for k in LOOPBACK_KEYWORDS) or ip == "127.0.0.1":
        return "loopback"
    if any(k in n for k in VM_KEYWORDS):
        return "vm"
    if any(k in n for k in VPN_KEYWORDS):
        return "vpn"
    if any(k in n for k in HOTSPOT_KEYWORDS):
        return "hotspot"
    if ip and ip.startswith("192.168.137."):
        return "hotspot"
    if any(k in n for k in WIFI_KEYWORDS):
        return "wifi"
    if any(k in n for k in ETHERNET_KEYWORDS):
        return "ethernet"
    if ip and not ip.startswith("169.254") and ip != "127.0.0.1":
        return "ethernet"
    return "unknown"


def _priority(itype: str, ip: str) -> int:
    base = {
        "wifi": 100, "ethernet": 90, "hotspot": 70,
        "vpn": 40, "unknown": 20, "vm": 10, "loopback": 5,
    }.get(itype, 15)
    if ip and not ip.startswith("169.254") and ip != "127.0.0.1":
        base += 20
    return base


def get_labelled_interfaces() -> Dict[str, str]:
    """
    Return ordered {display_label: raw_device_path} for all interfaces.
    Best real interface (WiFi/Ethernet) is listed first.
    """
    if not SCAPY_AVAILABLE:
        return {}
    try:
        raw_list = get_if_list()
    except Exception:
        return {}

    guid_map = _guid_to_name_registry()
    all_ips  = _get_all_ips()
    scored   = []

    for raw in raw_list:
        guid_match = re.search(r'\{([0-9A-F\-]+)\}', raw, re.IGNORECASE)

        if "Loopback" in raw and not guid_match:
            scored.append((5, "[Loopback] Npcap Loopback Adapter (127.0.0.1)", raw))
            continue

        if not guid_match:
            scored.append((1, f"[Unknown]  {raw[:40]}", raw))
            continue

        guid     = guid_match.group(1).upper()
        friendly = guid_map.get(guid, guid_map.get("{" + guid + "}", ""))
        if not friendly:
            friendly = f"Interface {{{guid[:8]}...}}"

        ip     = all_ips.get(friendly.lower(), "")
        itype  = _classify(friendly, ip)
        icon   = TYPE_ICONS.get(itype, "[Unknown] ")
        label  = f"{icon} {friendly}{f' ({ip})' if ip else ''}"
        scored.append((_priority(itype, ip), label, raw))

    scored.sort(key=lambda x: x[0], reverse=True)
    return {label: raw for _, label, raw in scored}


def get_best_interface(labelled: Dict[str, str]) -> Optional[str]:
    """Return display label of best real interface (WiFi > Ethernet > Hotspot)."""
    for label in labelled:
        t = label.strip().lower()
        if t.startswith("[wifi]") or t.startswith("[ethernet]") \
                or t.startswith("[hotspot]"):
            return label
    for label in labelled:
        t = label.strip().lower()
        if not t.startswith("[loopback]") and not t.startswith("[vm]"):
            return label
    return next(iter(labelled), None)


# ── PacketCapture ─────────────────────────────────────────────────────────────

class PacketCapture:
    """
    Live packet capture engine.

    Runs Scapy's sniff() in a background daemon thread.
    Every captured packet is normalized via normalization.normalize_packet()
    before being pushed to the detection queue — no protocol parsing happens
    in this class.

    Evidence buffer stores raw Scapy packets for PCAP export.
    """

    # Filter keywords for virtual NDIS layers (not real adapters)
    VIRTUAL_KEYWORDS = [
        "-wfp native mac", "-qos packet scheduler", "-npcap packet driver",
        "-native wifi filter", "-ndis light-weight", "-virtualbox ndis",
        "-wifi filter driver", "-802.3 mac layer", "wan miniport",
        "teredo tunneling", "isatap", "microsoft kernel debug",
        "microsoft ip-https", "microsoft teredo", "6to4 adapter", "bluetooth",
    ]

    def __init__(self, packet_queue: queue.Queue, interface: str = None):
        self.packet_queue     = packet_queue
        self.interface        = interface
        self._running         = False
        self._thread          = None
        self._evidence_buffer = []
        self._buffer_lock     = threading.Lock()
        self.MAX_BUFFER       = 200
        self._pkt_count       = 0
        self._seen_sources    = set()
        self._dropped         = 0

    # ── Public Interface ──────────────────────────────────────────────────────

    @staticmethod
    def list_interfaces() -> list:
        """Return raw Scapy interface device paths."""
        if not SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except Exception:
            return []

    @staticmethod
    def list_interfaces_friendly() -> Dict[str, str]:
        """
        Return {friendly_label: device_path} filtered to real adapters only.
        Excludes virtual NDIS filter stack components.
        """
        if not SCAPY_AVAILABLE:
            return {}

        result = {}
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                name       = iface.get("name", "")
                desc       = iface.get("description", "")
                ips        = iface.get("ips", [])
                guid       = iface.get("guid", "")
                desc_lower = desc.lower()

                if any(kw in desc_lower or kw in name.lower()
                       for kw in PacketCapture.VIRTUAL_KEYWORDS):
                    continue

                ip_str = next(
                    (ip for ip in ips if ":" not in ip
                     and not ip.startswith("169.254")),
                    ips[0] if ips else ""
                )
                label = f"{desc}{f' ({ip_str})' if ip_str else ''}" if desc else name

                if guid:
                    dev_path = "\\Device\\NPF_" + "{" + guid.strip("{}") + "}"
                else:
                    dev_path = name

                if label and dev_path:
                    result[label] = dev_path

            if result:
                return result
        except Exception:
            pass

        try:
            return {iface: iface for iface in get_if_list()}
        except Exception:
            return {}

    def start(self):
        """Start packet capture in a background daemon thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Run: pip install scapy\n"
                "Also install Npcap from https://npcap.com"
            )
        if normalize_packet is None:
            raise RuntimeError(
                "normalization.py not found. "
                "Ensure normalization.py is in the project directory."
            )
        if self._running:
            return

        # Normalise brace escaping that Python f-strings can introduce
        if self.interface and "NPF_" in self.interface:
            self.interface = re.sub(r'\{\{([^}]+)\}\}', r'{\1}', self.interface)
            self.interface = self.interface.replace("{{", "{").replace("}}", "}")

        self._running = True
        self._thread  = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        logger.info(f"Packet capture started on: {self.interface or 'default interface'}")

    def stop(self):
        """Signal the capture loop to stop."""
        self._running = False
        logger.info("Packet capture stopped.")

    def get_evidence_packets(self) -> list:
        """Return a copy of the raw packet evidence buffer for PCAP export."""
        with self._buffer_lock:
            return list(self._evidence_buffer)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _capture_loop(self):
        """Scapy sniff loop — runs until stop() is called."""
        sniff_kwargs = {
            "prn":         self._handle_packet,
            "store":       False,
            "promisc":     True,
            "stop_filter": lambda _: not self._running,
        }
        if self.interface:
            sniff_kwargs["iface"] = self.interface

        try:
            sniff(**sniff_kwargs)
        except Exception as e:
            logger.error(f"Sniff error: {e}")

    def _handle_packet(self, raw_pkt):
        """
        Handle one raw Scapy packet.

        Steps:
          1. Append to evidence buffer (always, for PCAP export)
          2. Delegate ALL field extraction to normalize_packet()
          3. Push normalized dict to detection queue

        No protocol checks are performed here — normalization.py owns that
        logic exclusively to maintain strict separation of concerns.
        """
        # ── Evidence buffer (raw packets for PCAP export) ────────────────────
        with self._buffer_lock:
            self._evidence_buffer.append(raw_pkt)
            if len(self._evidence_buffer) > self.MAX_BUFFER:
                self._evidence_buffer.pop(0)

        # ── Normalize via IP.proto-based router ──────────────────────────────
        packet_info = normalize_packet(raw_pkt)
        if packet_info is None:
            return  # Non-IP or unsupported protocol — silently discard

        # Attach raw packet reference for evidence logger (optional, pop-able)
        packet_info["raw"] = raw_pkt

        # ── Logging ──────────────────────────────────────────────────────────
        self._pkt_count += 1
        src = packet_info["src"]

        if src not in self._seen_sources:
            self._seen_sources.add(src)
            proto = packet_info["protocol"]
            flags = packet_info.get("flags")
            logger.debug(
                f"[NEW SRC] {src} -> {packet_info['dst']} | {proto}"
                + (f" flags={flags}" if flags else "")
            )

        if self._pkt_count % 500 == 0:
            logger.info(
                f"[PacketCapture] {self._pkt_count:,} packets captured | "
                f"{len(self._seen_sources)} unique sources | "
                f"{self._dropped} dropped"
            )

        # ── Push to detection queue ──────────────────────────────────────────
        try:
            self.packet_queue.put_nowait(packet_info)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 100 == 1:
                logger.warning(
                    f"[PacketCapture] Queue full — {self._dropped} packets dropped. "
                    f"Detection engine may be overloaded."
                )
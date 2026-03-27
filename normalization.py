"""
normalization.py
----------------
Packet Normalization Layer for NIDS

Converts raw Scapy packets into a flat, canonical dictionary schema.
Protocol routing is determined EXCLUSIVELY by IP.proto field — never
by Scapy layer-presence checks — preventing cross-protocol false positives
caused by encapsulated headers (e.g. TCP headers inside ICMP error payloads).

Canonical Schema
----------------
{
    "src":        str,    # Source IP address
    "dst":        str,    # Destination IP address
    "protocol":   str,    # "TCP" | "UDP" | "ICMP" | "OTHER"
    "src_port":   int|None,  # TCP/UDP only; None for ICMP
    "dst_port":   int|None,  # TCP/UDP only; None for ICMP
    "flags":      str|None,  # TCP only (e.g. "S", "SA"); None for UDP/ICMP
    "icmp_type":  int|None,  # ICMP only; None for TCP/UDP
    "icmp_code":  int|None,  # ICMP only; None for TCP/UDP
    "size":       int,    # Total packet size in bytes
    "timestamp":  float,  # Unix capture timestamp
}

IP Protocol Numbers (IANA)
--------------------------
  1  = ICMP
  6  = TCP
  17 = UDP

Design Notes
------------
- Uses packet[IP].proto as the single source of truth for protocol type.
- NEVER uses Scapy's `TCP in packet` / `UDP in packet` / `ICMP in packet`
  for protocol classification — these traverse the full packet tree and
  can match encapsulated layer headers inside ICMP error payloads.
- Fields irrelevant to the identified protocol are always set to None.
- Returns None for non-IP packets or unsupported protocols so the caller
  can discard them without branching logic.
"""

import time
import logging
from typing import Optional

logger = logging.getLogger("Normalization")

# ── IANA IP Protocol Numbers ────────────────────────────────────────────────

PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# ── TCP Flag Bitmask Map ─────────────────────────────────────────────────────

_TCP_FLAG_MAP = [
    (0x001, "F"),   # FIN
    (0x002, "S"),   # SYN
    (0x004, "R"),   # RST
    (0x008, "P"),   # PSH
    (0x010, "A"),   # ACK
    (0x020, "U"),   # URG
    (0x040, "E"),   # ECE
    (0x080, "C"),   # CWR
]


def _decode_tcp_flags(flag_int: int) -> str:
    """Convert integer TCP flags to a canonical flag string (e.g. 'SA', 'S')."""
    return "".join(ch for bit, ch in _TCP_FLAG_MAP if flag_int & bit)


# ── Public API ───────────────────────────────────────────────────────────────

def normalize_packet(raw_pkt) -> Optional[dict]:
    """
    Normalize a raw Scapy packet into the canonical NIDS packet schema.

    Args:
        raw_pkt: A raw Scapy packet object from sniff().

    Returns:
        A canonical packet dict, or None if the packet should be discarded
        (non-IP, unsupported protocol, or missing required layers).

    Protocol Routing
    ----------------
    Classification is done via packet[IP].proto exclusively:
        proto=1  → ICMP  (ports=None, flags=None)
        proto=6  → TCP   (icmp_type=None, icmp_code=None)
        proto=17 → UDP   (flags=None, icmp_type=None, icmp_code=None)
        other    → None  (packet discarded)

    This prevents false positives from Scapy's deep-parse operator which
    would otherwise detect TCP headers encapsulated inside ICMP payloads.
    """
    try:
        # ── Gate 1: Must be an IP packet ────────────────────────────────────
        from scapy.layers.inet import IP
        if IP not in raw_pkt:
            return None

        ip_layer = raw_pkt[IP]
        proto_num = ip_layer.proto   # Definitive protocol — do not override

        base = {
            "src":       ip_layer.src,
            "dst":       ip_layer.dst,
            "size":      len(raw_pkt),
            "timestamp": time.time(),
            "payload":   _extract_payload(raw_pkt),  # Extract raw payload
        }

        # ── Gate 2: Route by IP.proto — one branch, no fallback chain ───────

        if proto_num == PROTO_TCP:
            return _normalize_tcp(raw_pkt, ip_layer, base)

        elif proto_num == PROTO_UDP:
            return _normalize_udp(raw_pkt, ip_layer, base)

        elif proto_num == PROTO_ICMP:
            return _normalize_icmp(raw_pkt, ip_layer, base)

        else:
            # Non-TCP/UDP/ICMP traffic (GRE, ESP, OSPF, etc.) — discard
            logger.debug(
                f"[Normalization] Unsupported IP proto={proto_num} "
                f"from {ip_layer.src} — discarded."
            )
            return None

    except Exception as exc:
        logger.warning(f"[Normalization] Packet parse error: {exc}")
        return None


# ── Protocol-Specific Normalizers ────────────────────────────────────────────

def _extract_payload(raw_pkt) -> Optional[bytes]:
    """
    Extract application-layer payload from a packet.
    
    Returns the raw payload bytes, or None if no payload data.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, Raw
        
        if IP not in raw_pkt:
            return None
        
        ip_layer = raw_pkt[IP]
        payload_layer = ip_layer.payload
        
        # Traverse layers looking for Raw data
        while payload_layer:
            if isinstance(payload_layer, Raw):
                return payload_layer.load
            payload_layer = payload_layer.payload
        
        return None
    except Exception as e:
        logger.debug(f"Payload extraction error: {e}")
        return None

def _normalize_tcp(raw_pkt, ip_layer, base: dict) -> Optional[dict]:
    """
    Extract TCP fields from a packet confirmed as TCP via IP.proto=6.

    Only reads the FIRST TCP layer (ip_layer.payload) — never uses
    `TCP in raw_pkt` which would traverse into ICMP error payloads.
    """
    from scapy.layers.inet import TCP

    # Access TCP directly as IP payload, not via deep-search operator
    tcp_layer = ip_layer.payload
    if not isinstance(tcp_layer, TCP):
        logger.debug(
            f"[Normalization] IP.proto=6 but payload is not TCP "
            f"(got {type(tcp_layer).__name__}) — discarded."
        )
        return None

    flags_str = _decode_tcp_flags(int(tcp_layer.flags))

    return {
        **base,
        "protocol":  "TCP",
        "src_port":  int(tcp_layer.sport),
        "dst_port":  int(tcp_layer.dport),
        "flags":     flags_str,   # May be "" for NULL scan — always a str
        "icmp_type": None,        # Strict isolation — irrelevant to TCP
        "icmp_code": None,
    }


def _normalize_udp(raw_pkt, ip_layer, base: dict) -> Optional[dict]:
    """
    Extract UDP fields from a packet confirmed as UDP via IP.proto=17.
    """
    from scapy.layers.inet import UDP

    udp_layer = ip_layer.payload
    if not isinstance(udp_layer, UDP):
        logger.debug(
            f"[Normalization] IP.proto=17 but payload is not UDP "
            f"(got {type(udp_layer).__name__}) — discarded."
        )
        return None

    return {
        **base,
        "protocol":  "UDP",
        "src_port":  int(udp_layer.sport),
        "dst_port":  int(udp_layer.dport),
        "flags":     None,        # Strict isolation — UDP has no flags
        "icmp_type": None,        # Strict isolation — irrelevant to UDP
        "icmp_code": None,
    }


def _normalize_icmp(raw_pkt, ip_layer, base: dict) -> Optional[dict]:
    """
    Extract ICMP fields from a packet confirmed as ICMP via IP.proto=1.

    ICMP error messages (type 3 Destination Unreachable, type 11 TTL
    Exceeded, etc.) embed the original IP+TCP/UDP headers as payload.
    Because we access ICMP only via ip_layer.payload, the inner TCP/UDP
    headers are never mistakenly promoted to top-level protocol status.
    """
    from scapy.layers.inet import ICMP

    icmp_layer = ip_layer.payload
    if not isinstance(icmp_layer, ICMP):
        logger.debug(
            f"[Normalization] IP.proto=1 but payload is not ICMP "
            f"(got {type(icmp_layer).__name__}) — discarded."
        )
        return None

    return {
        **base,
        "protocol":  "ICMP",
        "src_port":  None,        # Strict isolation — ICMP has no ports
        "dst_port":  None,
        "flags":     None,        # Strict isolation — ICMP has no TCP flags
        "icmp_type": int(icmp_layer.type),
        "icmp_code": int(icmp_layer.code),
    }

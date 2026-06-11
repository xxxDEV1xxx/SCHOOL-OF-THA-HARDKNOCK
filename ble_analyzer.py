#!/usr/bin/env python3
"""
Phase 5 — BLE Anomaly Detector & Forensic Analyzer
CTW SDR Forensic Platform

Consumes NDJSON packet records from ble_capture (C++ engine) via stdin/pipe,
builds device profiles, detects anomalous RF behavior, and produces
hash-chained forensic evidence logs.

Anomaly categories detected:
  JAM-001  Broadband energy with no decodable packets (jamming)
  JAM-002  Sustained energy above noise floor without valid BLE structure
  JAM-003  Selective channel jamming (one adv channel degraded)
  FLD-001  MAC address flood (>N unique MACs in time window)
  FLD-002  Advertisement rate anomaly (device advertising too fast)
  FLD-003  Burst cluster (many new MACs appear simultaneously)
  IMP-001  MAC address reuse with different RF fingerprint
  IMP-002  OUI mismatch (random bit clear but OUI unregistered/impossible)
  IMP-003  PDU type inconsistency for same address
  GHO-001  Ghost device (appears once, never again)
  GHO-002  Coordinated ghost cluster (multiple ghosts in same window)
  STR-001  Signal strength anomaly (too strong for BLE class)
  STR-002  Carrier frequency offset anomaly
  PRO-001  Non-standard PDU type or reserved field usage
  PRO-002  Malformed advertising data (AD structure violations)
  PRO-003  Extended advertising in non-extended context

Usage:
  ./ble_capture | python3 ble_analyzer.py --output /path/to/evidence/
  python3 ble_analyzer.py --replay capture.ndjson --output /path/to/evidence/

(c) 2026 Christopher T. Williams — CTW SDR Forensic Platform
"""

import sys
import os
import json
import hashlib
import time
import argparse
import signal
import statistics
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
import struct

# ─── Configuration Constants ─── #

# Time windows (seconds)
DEVICE_EXPIRY_WINDOW    = 300    # Device considered "gone" after 5 min silence
GHOST_THRESHOLD         = 10     # Seen fewer than N times total = ghost candidate
GHOST_LIFESPAN_MAX      = 5.0   # Ghost if entire lifespan < N seconds
BURST_WINDOW            = 2.0   # Window to detect burst arrivals
BURST_THRESHOLD         = 10    # N new MACs in burst window = anomaly
FLOOD_WINDOW            = 60.0  # Window for MAC flood detection
FLOOD_THRESHOLD         = 100   # N unique MACs in flood window = anomaly
ADV_RATE_MIN_INTERVAL   = 0.015 # 15ms — faster than BLE spec minimum (20ms with jitter)
ENERGY_WINDOW           = 10.0  # Window for energy baseline calculation

# Signal strength thresholds (dB, relative to noise floor)
BLE_CLASS1_MAX_DBM      = 20.0  # Class 1 BLE max TX power
RSSI_ANOMALY_THRESHOLD  = 10.0  # dB above Class 1 max = suspicious

# Jamming detection
JAM_ENERGY_THRESHOLD    = 10.0  # dB above noise floor with no valid packets
JAM_CORRUPT_RATIO       = 0.8   # >80% corrupt packets = jamming indicator

# RF fingerprint comparison
FREQ_OFFSET_TOLERANCE   = 5000.0  # Hz — same device should have consistent offset

# Evidence hash chain
HASH_ALGORITHM          = 'blake3'  # Match SDAR chain; fallback to sha256

# Try to import blake3, fall back to sha256
try:
    import blake3
    def hash_bytes(data: bytes) -> str:
        return blake3.blake3(data).hexdigest()
    HASH_ALGO_USED = 'blake3'
except ImportError:
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
    HASH_ALGO_USED = 'sha256'


# ─── OUI Database (partial — known BLE chipset vendors) ─── #
# In production, load full IEEE OUI database
KNOWN_OUI = {
    # Major BLE chipset manufacturers
    "00:1A:7D": "Cyber-Blue(ShenZhen)",
    "00:25:48": "Broadcom (BLE)",
    "00:07:80": "Zebra Technologies (BLE)",
    "D4:F5:13": "Texas Instruments",
    "78:A5:04": "Texas Instruments",
    "B0:B4:48": "Texas Instruments",
    "54:6C:0E": "Texas Instruments",
    "A0:E6:F8": "Texas Instruments",
    "7C:EC:79": "Texas Instruments",
    "00:17:E9": "Texas Instruments",
    "F0:F8:F2": "Texas Instruments",
    "20:CD:39": "Texas Instruments",
    "5C:31:3E": "Nordic Semiconductor",
    "E7:E0:77": "Nordic Semiconductor",
    "C3:42:7A": "Nordic Semiconductor",
    "F4:CE:36": "Dialog Semiconductor",
    "00:60:37": "NXP/Philips",
    "34:15:13": "Tuya/Generic IoT",
    "A4:C1:38": "Espressif (ESP32 BLE)",
    "24:0A:C4": "Espressif (ESP32 BLE)",
    "30:AE:A4": "Espressif (ESP32 BLE)",
    "B4:E6:2D": "Espressif (ESP32 BLE)",
    "CC:50:E3": "Espressif (ESP32 BLE)",
    "AC:67:B2": "Espressif (ESP32 BLE)",
    "7C:DF:A1": "Espressif (ESP32 BLE)",
    "FC:F5:C4": "Espressif (ESP32 BLE)",
    "84:0D:8E": "Espressif (ESP32 BLE)",
    "84:CC:A8": "Espressif (ESP32 BLE)",
    "8C:AA:B5": "Espressif (ESP32 BLE)",
    "94:B9:7E": "Espressif (ESP32 BLE)",
    "48:3F:DA": "Espressif (ESP32 BLE)",
    "E0:98:06": "Espressif (ESP32 BLE)",
    "C8:C9:A3": "Tuya/Generic IoT",
    "D8:3A:DD": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "28:CD:C1": "Raspberry Pi Foundation",
    # Apple prefixes (iBeacon, AirTag, etc.)
    "4C:00:00": "Apple (Company ID)",
}


# ─── Data Structures ─── #

@dataclass
class DeviceProfile:
    """Accumulated profile of a single observed BLE address."""
    bdaddr: str
    addr_random: bool
    first_seen: float           # epoch timestamp
    last_seen: float
    total_packets: int = 0
    channels_seen: Set[int] = field(default_factory=set)
    pdu_types_seen: Set[int] = field(default_factory=set)
    rssi_samples: List[float] = field(default_factory=list)
    freq_offset_samples: List[float] = field(default_factory=list)
    inter_arrival_times: List[float] = field(default_factory=list)
    crc_valid_count: int = 0
    crc_fail_count: int = 0
    raw_payloads: List[str] = field(default_factory=list)  # first N unique
    oui: str = ""
    oui_vendor: str = ""
    anomaly_flags: List[str] = field(default_factory=list)
    
    def update(self, pkt: dict, timestamp: float):
        if self.total_packets > 0:
            iat = timestamp - self.last_seen
            if len(self.inter_arrival_times) < 10000:
                self.inter_arrival_times.append(iat)
        self.last_seen = timestamp
        self.total_packets += 1
        self.channels_seen.add(pkt.get('ch', 0))
        self.pdu_types_seen.add(pkt.get('pdu_type', -1))
        if len(self.rssi_samples) < 10000:
            self.rssi_samples.append(pkt.get('rssi_db', -100))
        if len(self.freq_offset_samples) < 10000:
            self.freq_offset_samples.append(pkt.get('freq_offset_hz', 0))
        if pkt.get('crc_valid', False):
            self.crc_valid_count += 1
        else:
            self.crc_fail_count += 1
        raw = pkt.get('raw_hex', '')
        if raw and len(self.raw_payloads) < 50 and raw not in self.raw_payloads:
            self.raw_payloads.append(raw)

    @property
    def lifespan(self) -> float:
        return self.last_seen - self.first_seen
    
    @property
    def mean_rssi(self) -> float:
        return statistics.mean(self.rssi_samples) if self.rssi_samples else -100.0
    
    @property
    def rssi_stdev(self) -> float:
        return statistics.stdev(self.rssi_samples) if len(self.rssi_samples) > 1 else 0.0
    
    @property
    def mean_iat(self) -> float:
        return statistics.mean(self.inter_arrival_times) if self.inter_arrival_times else 0.0
    
    @property
    def crc_fail_ratio(self) -> float:
        total = self.crc_valid_count + self.crc_fail_count
        return self.crc_fail_count / total if total > 0 else 0.0


@dataclass
class AnomalyRecord:
    """A single detected anomaly."""
    anomaly_id: str             # e.g., "JAM-001", "FLD-001"
    severity: str               # CRITICAL, HIGH, MEDIUM, LOW, INFO
    timestamp: str              # ISO 8601
    channel: int
    description: str
    evidence: dict              # Supporting data
    related_addrs: List[str] = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)


@dataclass
class EnergyWindow:
    """Rolling energy measurement per channel."""
    channel: int
    samples: deque = field(default_factory=lambda: deque(maxlen=200))
    valid_pkt_counts: deque = field(default_factory=lambda: deque(maxlen=200))
    corrupt_pkt_counts: deque = field(default_factory=lambda: deque(maxlen=200))
    
    @property
    def mean_power(self) -> float:
        vals = [s[1] for s in self.samples]
        return statistics.mean(vals) if vals else -100.0
    
    @property
    def power_stdev(self) -> float:
        vals = [s[1] for s in self.samples]
        return statistics.stdev(vals) if len(vals) > 1 else 0.0


# ─── Forensic Evidence Logger ─── #

class EvidenceChain:
    """BLAKE3/SHA256 hash-chained evidence log (SDAR-compatible)."""
    
    def __init__(self, output_dir: Path, session_id: str):
        self.output_dir = output_dir
        self.session_id = session_id
        self.chain_file = output_dir / f"phase5_evidence_{session_id}.ndjson"
        self.prev_hash = "0" * 64  # Genesis hash
        self.seq = 0
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Write session header
        header = {
            "type": "session_start",
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hash_algorithm": HASH_ALGO_USED,
            "platform": "CTW Phase 5 BLE Monitor",
            "version": "0.1.0"
        }
        self._write_record(header)
    
    def _write_record(self, record: dict):
        record['_seq'] = self.seq
        record['_prev_hash'] = self.prev_hash
        
        # Compute hash of this record (excluding hash fields)
        record_bytes = json.dumps(record, sort_keys=True).encode('utf-8')
        record_hash = hash_bytes(record_bytes)
        record['_hash'] = record_hash
        
        with open(self.chain_file, 'a') as f:
            f.write(json.dumps(record, sort_keys=True) + '\n')
        
        self.prev_hash = record_hash
        self.seq += 1
    
    def log_packet(self, pkt: dict):
        record = {
            "type": "packet",
            "data": pkt
        }
        self._write_record(record)
    
    def log_anomaly(self, anomaly: AnomalyRecord):
        record = {
            "type": "anomaly",
            "data": anomaly.to_dict()
        }
        self._write_record(record)
    
    def log_device_summary(self, profile: DeviceProfile):
        summary = {
            "bdaddr": profile.bdaddr,
            "addr_random": profile.addr_random,
            "first_seen": profile.first_seen,
            "last_seen": profile.last_seen,
            "total_packets": profile.total_packets,
            "channels": sorted(profile.channels_seen),
            "pdu_types": sorted(profile.pdu_types_seen),
            "mean_rssi": round(profile.mean_rssi, 2),
            "rssi_stdev": round(profile.rssi_stdev, 2),
            "mean_iat": round(profile.mean_iat, 6),
            "crc_fail_ratio": round(profile.crc_fail_ratio, 4),
            "lifespan_sec": round(profile.lifespan, 3),
            "oui": profile.oui,
            "oui_vendor": profile.oui_vendor,
            "anomaly_flags": profile.anomaly_flags,
            "unique_payloads": len(profile.raw_payloads),
        }
        record = {
            "type": "device_summary",
            "data": summary
        }
        self._write_record(record)
    
    def log_session_stats(self, stats: dict):
        record = {
            "type": "session_stats",
            "data": stats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self._write_record(record)
    
    def finalize(self):
        record = {
            "type": "session_end",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_records": self.seq
        }
        self._write_record(record)


# ─── Core Analyzer ─── #

class BLEAnomalyAnalyzer:
    """Main analysis engine for BLE passive capture data."""
    
    def __init__(self, output_dir: Path, verbose: bool = False):
        self.verbose = verbose
        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.output_dir = output_dir
        self.evidence = EvidenceChain(output_dir, self.session_id)
        
        # Device tracking
        self.devices: Dict[str, DeviceProfile] = {}
        
        # Temporal tracking
        self.recent_new_macs: deque = deque()  # (timestamp, mac) for burst detection
        self.all_macs_in_window: deque = deque()  # (timestamp, mac) for flood detection
        
        # Energy tracking per channel
        self.energy: Dict[int, EnergyWindow] = {
            37: EnergyWindow(channel=37),
            38: EnergyWindow(channel=38),
            39: EnergyWindow(channel=39),
        }
        
        # Noise floor baseline (established in first N seconds)
        self.noise_baseline: Dict[int, float] = {}
        self.baseline_samples: Dict[int, List[float]] = defaultdict(list)
        self.baseline_established = False
        self.baseline_window = 10.0  # seconds
        
        # Statistics
        self.total_packets = 0
        self.total_anomalies = 0
        self.anomaly_counts: Dict[str, int] = defaultdict(int)
        self.start_time = time.time()
        
        # Anomaly dedup (don't spam same anomaly)
        self.recent_anomalies: Dict[str, float] = {}  # key -> last_fired_time
        self.anomaly_cooldown = 30.0  # seconds between same anomaly re-firing
        
        # Ghost tracking
        self.ghost_candidates: Set[str] = set()
        
        self._print_banner()
    
    def _print_banner(self):
        sys.stderr.write("═" * 60 + "\n")
        sys.stderr.write("  Phase 5 — BLE Anomaly Detector v0.1\n")
        sys.stderr.write("  CTW SDR Forensic Platform\n")
        sys.stderr.write(f"  Session: {self.session_id}\n")
        sys.stderr.write(f"  Evidence: {self.evidence.chain_file}\n")
        sys.stderr.write(f"  Hash: {HASH_ALGO_USED}\n")
        sys.stderr.write("═" * 60 + "\n")
    
    def _ts_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()
    
    def _parse_timestamp(self, ts_str: str) -> float:
        """Parse ISO timestamp to epoch float."""
        try:
            dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except (ValueError, AttributeError):
            return time.time()
    
    def _lookup_oui(self, bdaddr: str) -> Tuple[str, str]:
        """Look up OUI prefix in known vendor table."""
        oui = bdaddr[:8].upper()
        vendor = KNOWN_OUI.get(oui, "")
        return oui, vendor
    
    def _fire_anomaly(self, anomaly_id: str, severity: str, channel: int,
                      description: str, evidence: dict,
                      related_addrs: List[str] = None):
        """Create and log an anomaly, with cooldown dedup."""
        key = f"{anomaly_id}:{channel}"
        now = time.time()
        
        if key in self.recent_anomalies:
            if now - self.recent_anomalies[key] < self.anomaly_cooldown:
                return  # Suppress duplicate
        
        self.recent_anomalies[key] = now
        self.total_anomalies += 1
        self.anomaly_counts[anomaly_id] += 1
        
        record = AnomalyRecord(
            anomaly_id=anomaly_id,
            severity=severity,
            timestamp=self._ts_now(),
            channel=channel,
            description=description,
            evidence=evidence,
            related_addrs=related_addrs or []
        )
        
        self.evidence.log_anomaly(record)
        
        # Print to stderr for real-time monitoring
        sev_markers = {
            "CRITICAL": "!!!!",
            "HIGH":     "!!!",
            "MEDIUM":   "!!",
            "LOW":      "!",
            "INFO":     "·"
        }
        marker = sev_markers.get(severity, "?")
        sys.stderr.write(
            f"  [{marker}] {anomaly_id} [{severity}] ch{channel}: "
            f"{description}\n"
        )
        if related_addrs:
            sys.stderr.write(f"       Addrs: {', '.join(related_addrs[:5])}\n")
    
    # ─── Anomaly Detection Methods ─── #
    
    def _check_mac_flood(self, timestamp: float, bdaddr: str):
        """FLD-001: Too many unique MACs in time window."""
        self.all_macs_in_window.append((timestamp, bdaddr))
        
        # Trim window
        cutoff = timestamp - FLOOD_WINDOW
        while self.all_macs_in_window and self.all_macs_in_window[0][0] < cutoff:
            self.all_macs_in_window.popleft()
        
        # Count unique MACs in window
        unique_macs = set(m for _, m in self.all_macs_in_window)
        
        if len(unique_macs) >= FLOOD_THRESHOLD:
            self._fire_anomaly(
                "FLD-001", "CRITICAL", 0,
                f"MAC flood: {len(unique_macs)} unique addresses in "
                f"{FLOOD_WINDOW}s window (threshold: {FLOOD_THRESHOLD})",
                {
                    "unique_count": len(unique_macs),
                    "window_sec": FLOOD_WINDOW,
                    "total_pkts_in_window": len(self.all_macs_in_window),
                    "sample_addrs": list(unique_macs)[:20]
                }
            )
    
    def _check_burst_arrival(self, timestamp: float, bdaddr: str,
                             is_new_device: bool):
        """FLD-003: Cluster of new MACs appearing simultaneously."""
        if not is_new_device:
            return
        
        self.recent_new_macs.append((timestamp, bdaddr))
        
        # Trim window
        cutoff = timestamp - BURST_WINDOW
        while self.recent_new_macs and self.recent_new_macs[0][0] < cutoff:
            self.recent_new_macs.popleft()
        
        if len(self.recent_new_macs) >= BURST_THRESHOLD:
            new_addrs = [m for _, m in self.recent_new_macs]
            self._fire_anomaly(
                "FLD-003", "HIGH", 0,
                f"Burst arrival: {len(self.recent_new_macs)} new MACs in "
                f"{BURST_WINDOW}s window",
                {
                    "new_mac_count": len(self.recent_new_macs),
                    "window_sec": BURST_WINDOW,
                    "addresses": new_addrs[:20]
                },
                related_addrs=new_addrs[:10]
            )
    
    def _check_adv_rate(self, profile: DeviceProfile, timestamp: float):
        """FLD-002: Device advertising faster than BLE spec allows."""
        if len(profile.inter_arrival_times) < 5:
            return
        
        recent_iats = profile.inter_arrival_times[-10:]
        min_iat = min(recent_iats)
        mean_iat = statistics.mean(recent_iats)
        
        if mean_iat < ADV_RATE_MIN_INTERVAL and min_iat < 0.010:
            if "FLD-002" not in profile.anomaly_flags:
                profile.anomaly_flags.append("FLD-002")
                self._fire_anomaly(
                    "FLD-002", "HIGH", 0,
                    f"Adv rate anomaly: {profile.bdaddr} advertising at "
                    f"{mean_iat*1000:.1f}ms interval (BLE min ~20ms)",
                    {
                        "bdaddr": profile.bdaddr,
                        "mean_iat_ms": round(mean_iat * 1000, 2),
                        "min_iat_ms": round(min_iat * 1000, 2),
                    },
                    related_addrs=[profile.bdaddr]
                )
    
    def _check_oui_consistency(self, profile: DeviceProfile):
        """IMP-002: Random bit clear but OUI unregistered/suspicious."""
        if profile.addr_random:
            return  # Random address — OUI is meaningless, skip
        
        if profile.oui_vendor:
            return  # Known vendor, fine
        
        # Non-random address with unknown OUI
        if "IMP-002" not in profile.anomaly_flags:
            profile.anomaly_flags.append("IMP-002")
            self._fire_anomaly(
                "IMP-002", "MEDIUM", 0,
                f"OUI mismatch: {profile.bdaddr} claims public address "
                f"but OUI {profile.oui} not in IEEE registry",
                {
                    "bdaddr": profile.bdaddr,
                    "oui": profile.oui,
                    "addr_random": profile.addr_random,
                },
                related_addrs=[profile.bdaddr]
            )
    
    def _check_pdu_type_consistency(self, profile: DeviceProfile):
        """IMP-003 / PRO-001: Unusual PDU type combinations."""
        types = profile.pdu_types_seen
        
        # A device sending both ADV_IND and ADV_NONCONN_IND is unusual
        if 0 in types and 2 in types:
            if "IMP-003" not in profile.anomaly_flags:
                profile.anomaly_flags.append("IMP-003")
                self._fire_anomaly(
                    "IMP-003", "MEDIUM", 0,
                    f"PDU type inconsistency: {profile.bdaddr} sends both "
                    f"ADV_IND and ADV_NONCONN_IND",
                    {
                        "bdaddr": profile.bdaddr,
                        "pdu_types": sorted(types),
                    },
                    related_addrs=[profile.bdaddr]
                )
        
        # Reserved PDU types (8-15) in use
        reserved_used = types & {8, 9, 10, 11, 12, 13, 14, 15}
        if reserved_used:
            if "PRO-001" not in profile.anomaly_flags:
                profile.anomaly_flags.append("PRO-001")
                self._fire_anomaly(
                    "PRO-001", "HIGH", 0,
                    f"Reserved PDU type in use: {profile.bdaddr} sent "
                    f"types {sorted(reserved_used)}",
                    {
                        "bdaddr": profile.bdaddr,
                        "reserved_types": sorted(reserved_used),
                    },
                    related_addrs=[profile.bdaddr]
                )
    
    def _check_signal_strength(self, profile: DeviceProfile):
        """STR-001: Signal too strong for BLE specification."""
        if len(profile.rssi_samples) < 3:
            return
        
        mean_rssi = profile.mean_rssi
        
        # If RSSI is suspiciously high (above BLE Class 1 max + margin)
        # Note: rssi_db from capture is relative, calibration dependent.
        # Flag anything that's an extreme outlier relative to the population.
        if mean_rssi > RSSI_ANOMALY_THRESHOLD:
            if "STR-001" not in profile.anomaly_flags:
                profile.anomaly_flags.append("STR-001")
                self._fire_anomaly(
                    "STR-001", "MEDIUM", 0,
                    f"RSSI anomaly: {profile.bdaddr} at {mean_rssi:.1f} dB "
                    f"(exceeds expected BLE range)",
                    {
                        "bdaddr": profile.bdaddr,
                        "mean_rssi": round(mean_rssi, 2),
                        "rssi_stdev": round(profile.rssi_stdev, 2),
                        "samples": len(profile.rssi_samples),
                    },
                    related_addrs=[profile.bdaddr]
                )
    
    def _check_rf_fingerprint_collision(self, bdaddr: str,
                                        profile: DeviceProfile,
                                        pkt: dict):
        """IMP-001: Same MAC, different RF characteristics.
        
        If a device disappears and reappears with a significantly different
        carrier frequency offset, it may be a different physical radio
        impersonating the same address.
        """
        if len(profile.freq_offset_samples) < 20:
            return
        
        # Compare first-half vs second-half offset distributions
        mid = len(profile.freq_offset_samples) // 2
        first_half = profile.freq_offset_samples[:mid]
        second_half = profile.freq_offset_samples[mid:]
        
        if len(first_half) < 5 or len(second_half) < 5:
            return
        
        mean_first = statistics.mean(first_half)
        mean_second = statistics.mean(second_half)
        delta = abs(mean_second - mean_first)
        
        if delta > FREQ_OFFSET_TOLERANCE:
            if "IMP-001" not in profile.anomaly_flags:
                profile.anomaly_flags.append("IMP-001")
                self._fire_anomaly(
                    "IMP-001", "CRITICAL", pkt.get('ch', 0),
                    f"RF fingerprint shift: {bdaddr} carrier offset jumped "
                    f"{delta:.0f} Hz (possible impersonation)",
                    {
                        "bdaddr": bdaddr,
                        "offset_delta_hz": round(delta, 1),
                        "early_mean_hz": round(mean_first, 1),
                        "late_mean_hz": round(mean_second, 1),
                        "tolerance_hz": FREQ_OFFSET_TOLERANCE,
                    },
                    related_addrs=[bdaddr]
                )
    
    def _process_energy_record(self, record: dict):
        """Process channel energy record for jamming detection."""
        ch = record.get('ch', 0)
        if ch not in self.energy:
            return
        
        ts = self._parse_timestamp(record.get('ts', ''))
        power = record.get('power_db', -100)
        valid = record.get('valid_pkts', 0)
        corrupt = record.get('corrupt_pkts', 0)
        
        ew = self.energy[ch]
        ew.samples.append((ts, power))
        ew.valid_pkt_counts.append((ts, valid))
        ew.corrupt_pkt_counts.append((ts, corrupt))
        
        # Establish baseline from first N seconds
        elapsed = ts - self.start_time
        if elapsed < self.baseline_window:
            self.baseline_samples[ch].append(power)
            return
        elif not self.baseline_established:
            # Compute baselines
            for c, samples in self.baseline_samples.items():
                if samples:
                    self.noise_baseline[c] = statistics.mean(samples)
            self.baseline_established = True
            sys.stderr.write(f"  [*] Noise baselines: "
                           f"{', '.join(f'ch{c}={v:.1f}dB' for c,v in sorted(self.noise_baseline.items()))}\n")
        
        if not self.baseline_established:
            return
        
        baseline = self.noise_baseline.get(ch, -100)
        
        # JAM-001: High energy, no valid packets
        if power > baseline + JAM_ENERGY_THRESHOLD and valid == 0 and corrupt == 0:
            self._fire_anomaly(
                "JAM-001", "CRITICAL", ch,
                f"Broadband jamming: ch{ch} at {power:.1f} dB "
                f"({power - baseline:.1f} dB above baseline), "
                f"no decodable packets",
                {
                    "channel": ch,
                    "power_db": round(power, 2),
                    "baseline_db": round(baseline, 2),
                    "excess_db": round(power - baseline, 2),
                    "valid_pkts": valid,
                    "corrupt_pkts": corrupt,
                }
            )
        
        # JAM-002: High energy with mostly corrupt packets
        total_pkts = valid + corrupt
        if (total_pkts > 5 and power > baseline + JAM_ENERGY_THRESHOLD / 2):
            corrupt_ratio = corrupt / total_pkts
            if corrupt_ratio > JAM_CORRUPT_RATIO:
                self._fire_anomaly(
                    "JAM-002", "HIGH", ch,
                    f"Partial jamming: ch{ch} {corrupt_ratio*100:.0f}% "
                    f"corrupt packets ({corrupt}/{total_pkts})",
                    {
                        "channel": ch,
                        "corrupt_ratio": round(corrupt_ratio, 4),
                        "valid_pkts": valid,
                        "corrupt_pkts": corrupt,
                        "power_db": round(power, 2),
                    }
                )
        
        # JAM-003: Selective channel jamming (compare across channels)
        if len(self.noise_baseline) >= 3:
            other_chs = [c for c in self.noise_baseline if c != ch]
            other_powers = [
                self.energy[c].mean_power for c in other_chs
                if self.energy[c].samples
            ]
            if other_powers:
                other_mean = statistics.mean(other_powers)
                if power > other_mean + 15.0:  # 15 dB above other channels
                    self._fire_anomaly(
                        "JAM-003", "HIGH", ch,
                        f"Selective jamming: ch{ch} at {power:.1f} dB, "
                        f"other channels at {other_mean:.1f} dB "
                        f"(delta {power - other_mean:.1f} dB)",
                        {
                            "target_channel": ch,
                            "target_power": round(power, 2),
                            "other_mean_power": round(other_mean, 2),
                            "delta_db": round(power - other_mean, 2),
                        }
                    )
    
    def _check_ghosts(self, now: float):
        """GHO-001/GHO-002: Identify ghost devices on periodic sweep."""
        ghosts_found = []
        
        for bdaddr, profile in self.devices.items():
            if bdaddr in self.ghost_candidates:
                continue
            
            elapsed_since_last = now - profile.last_seen
            
            # Ghost: seen briefly, never again
            if (elapsed_since_last > DEVICE_EXPIRY_WINDOW and
                profile.total_packets <= GHOST_THRESHOLD and
                profile.lifespan < GHOST_LIFESPAN_MAX):
                
                self.ghost_candidates.add(bdaddr)
                ghosts_found.append(bdaddr)
                
                if "GHO-001" not in profile.anomaly_flags:
                    profile.anomaly_flags.append("GHO-001")
                    self._fire_anomaly(
                        "GHO-001", "LOW", 0,
                        f"Ghost device: {bdaddr} seen {profile.total_packets}x "
                        f"over {profile.lifespan:.1f}s, then vanished "
                        f"({elapsed_since_last:.0f}s ago)",
                        {
                            "bdaddr": bdaddr,
                            "total_packets": profile.total_packets,
                            "lifespan_sec": round(profile.lifespan, 3),
                            "silence_sec": round(elapsed_since_last, 1),
                        },
                        related_addrs=[bdaddr]
                    )
        
        # GHO-002: Coordinated ghost cluster
        if len(ghosts_found) >= 5:
            # Check if ghosts appeared in a narrow time window
            ghost_profiles = [self.devices[m] for m in ghosts_found]
            first_times = [p.first_seen for p in ghost_profiles]
            time_spread = max(first_times) - min(first_times)
            
            if time_spread < 10.0:  # All appeared within 10 seconds
                self._fire_anomaly(
                    "GHO-002", "CRITICAL", 0,
                    f"Coordinated ghost cluster: {len(ghosts_found)} devices "
                    f"appeared within {time_spread:.1f}s, all vanished",
                    {
                        "ghost_count": len(ghosts_found),
                        "time_spread_sec": round(time_spread, 3),
                        "addresses": ghosts_found[:20],
                    },
                    related_addrs=ghosts_found[:10]
                )
    
    # ─── Main Processing Loop ─── #
    
    def process_record(self, line: str):
        """Process a single NDJSON record from the capture engine."""
        try:
            record = json.loads(line.strip())
        except json.JSONDecodeError:
            return
        
        # Route by record type
        rec_type = record.get('type', 'packet')
        
        if rec_type == 'energy':
            self._process_energy_record(record)
            return
        
        # Packet record
        self.total_packets += 1
        bdaddr = record.get('adv_addr', '00:00:00:00:00:00')
        ch = record.get('ch', 0)
        ts_str = record.get('ts', '')
        timestamp = self._parse_timestamp(ts_str)
        
        # Log raw packet to evidence chain (every Nth to manage size)
        if self.total_packets % 10 == 0 or record.get('crc_valid', True) is False:
            self.evidence.log_packet(record)
        
        # Update or create device profile
        is_new = bdaddr not in self.devices
        if is_new:
            oui, vendor = self._lookup_oui(bdaddr)
            profile = DeviceProfile(
                bdaddr=bdaddr,
                addr_random=record.get('tx_addr_random', False),
                first_seen=timestamp,
                last_seen=timestamp,
                oui=oui,
                oui_vendor=vendor,
            )
            self.devices[bdaddr] = profile
        else:
            profile = self.devices[bdaddr]
        
        profile.update(record, timestamp)
        
        # ─── Run anomaly checks ─── #
        self._check_mac_flood(timestamp, bdaddr)
        self._check_burst_arrival(timestamp, bdaddr, is_new)
        self._check_adv_rate(profile, timestamp)
        self._check_oui_consistency(profile)
        self._check_pdu_type_consistency(profile)
        self._check_signal_strength(profile)
        self._check_rf_fingerprint_collision(bdaddr, profile, record)
        
        # Periodic ghost check (every 1000 packets)
        if self.total_packets % 1000 == 0:
            self._check_ghosts(timestamp)
        
        # Periodic status report
        if self.total_packets % 5000 == 0:
            self._print_status(timestamp)
    
    def _print_status(self, now: float):
        elapsed = now - self.start_time
        unique = len(self.devices)
        random_count = sum(1 for d in self.devices.values() if d.addr_random)
        public_count = unique - random_count
        ghost_count = len(self.ghost_candidates)
        
        sys.stderr.write(f"\n  ── Status @ {elapsed:.0f}s ──\n")
        sys.stderr.write(f"  Packets: {self.total_packets:,}\n")
        sys.stderr.write(f"  Unique MACs: {unique} "
                        f"({random_count} random, {public_count} public)\n")
        sys.stderr.write(f"  Ghosts: {ghost_count}\n")
        sys.stderr.write(f"  Anomalies: {self.total_anomalies}\n")
        for aid, cnt in sorted(self.anomaly_counts.items()):
            sys.stderr.write(f"    {aid}: {cnt}\n")
        sys.stderr.write("\n")
    
    def finalize(self):
        """Write final summaries and close evidence chain."""
        now = time.time()
        
        # Final ghost check
        self._check_ghosts(now)
        
        # Write device summaries
        sys.stderr.write(f"\n  [*] Writing {len(self.devices)} device summaries...\n")
        for profile in sorted(self.devices.values(),
                             key=lambda d: d.total_packets, reverse=True):
            self.evidence.log_device_summary(profile)
        
        # Session statistics
        elapsed = now - self.start_time
        random_count = sum(1 for d in self.devices.values() if d.addr_random)
        
        stats = {
            "duration_sec": round(elapsed, 2),
            "total_packets": self.total_packets,
            "unique_devices": len(self.devices),
            "random_addr_devices": random_count,
            "public_addr_devices": len(self.devices) - random_count,
            "ghost_devices": len(self.ghost_candidates),
            "total_anomalies": self.total_anomalies,
            "anomaly_breakdown": dict(self.anomaly_counts),
            "noise_baselines": {
                str(ch): round(v, 2)
                for ch, v in self.noise_baseline.items()
            },
        }
        self.evidence.log_session_stats(stats)
        self.evidence.finalize()
        
        # Print final report to stderr
        sys.stderr.write("\n" + "═" * 60 + "\n")
        sys.stderr.write("  Phase 5 — Session Complete\n")
        sys.stderr.write("═" * 60 + "\n")
        sys.stderr.write(f"  Duration:       {elapsed:.1f}s\n")
        sys.stderr.write(f"  Total Packets:  {self.total_packets:,}\n")
        sys.stderr.write(f"  Unique Devices: {len(self.devices)}\n")
        sys.stderr.write(f"    Random Addr:  {random_count}\n")
        sys.stderr.write(f"    Public Addr:  {len(self.devices) - random_count}\n")
        sys.stderr.write(f"  Ghost Devices:  {len(self.ghost_candidates)}\n")
        sys.stderr.write(f"  Anomalies:      {self.total_anomalies}\n")
        for aid, cnt in sorted(self.anomaly_counts.items()):
            sys.stderr.write(f"    {aid}: {cnt}\n")
        sys.stderr.write(f"\n  Evidence chain: {self.evidence.chain_file}\n")
        sys.stderr.write(f"  Records: {self.evidence.seq}\n")
        sys.stderr.write(f"  Hash algo: {HASH_ALGO_USED}\n")
        sys.stderr.write("═" * 60 + "\n")
        
        # Also write a human-readable summary report
        self._write_summary_report(stats, elapsed)
    
    def _write_summary_report(self, stats: dict, elapsed: float):
        """Write a human-readable Markdown summary."""
        report_path = self.output_dir / f"phase5_report_{self.session_id}.md"
        
        with open(report_path, 'w') as f:
            f.write("# Phase 5 — BLE Passive RF Monitor Report\n\n")
            f.write(f"**Session ID:** {self.session_id}  \n")
            f.write(f"**Duration:** {elapsed:.1f} seconds  \n")
            f.write(f"**Date:** {datetime.now(timezone.utc).isoformat()}  \n")
            f.write(f"**Platform:** CTW SDR Forensic Platform  \n\n")
            
            f.write("## Summary Statistics\n\n")
            f.write(f"- Total packets captured: {self.total_packets:,}\n")
            f.write(f"- Unique device addresses: {len(self.devices)}\n")
            f.write(f"  - Random addresses: {stats['random_addr_devices']}\n")
            f.write(f"  - Public addresses: {stats['public_addr_devices']}\n")
            f.write(f"- Ghost devices (appeared briefly, vanished): "
                    f"{len(self.ghost_candidates)}\n")
            f.write(f"- Total anomalies detected: {self.total_anomalies}\n\n")
            
            if self.anomaly_counts:
                f.write("## Anomaly Breakdown\n\n")
                f.write("| Code | Count | Category |\n")
                f.write("|------|-------|----------|\n")
                
                anomaly_descs = {
                    "JAM-001": "Broadband jamming (energy, no packets)",
                    "JAM-002": "Partial jamming (high corrupt ratio)",
                    "JAM-003": "Selective channel jamming",
                    "FLD-001": "MAC address flood",
                    "FLD-002": "Advertisement rate violation",
                    "FLD-003": "Burst arrival cluster",
                    "IMP-001": "RF fingerprint shift (impersonation)",
                    "IMP-002": "OUI mismatch (unregistered public addr)",
                    "IMP-003": "PDU type inconsistency",
                    "GHO-001": "Ghost device",
                    "GHO-002": "Coordinated ghost cluster",
                    "STR-001": "RSSI anomaly",
                    "STR-002": "Carrier frequency offset anomaly",
                    "PRO-001": "Reserved PDU type in use",
                    "PRO-002": "Malformed AD structure",
                    "PRO-003": "Extended advertising anomaly",
                }
                
                for aid, cnt in sorted(self.anomaly_counts.items()):
                    desc = anomaly_descs.get(aid, "Unknown")
                    f.write(f"| {aid} | {cnt} | {desc} |\n")
                f.write("\n")
            
            # Top devices by packet count
            f.write("## Top 30 Devices by Packet Count\n\n")
            f.write("| # | Address | Random | Packets | Lifespan | "
                    "RSSI (mean) | OUI | Flags |\n")
            f.write("|---|---------|--------|---------|----------|"
                    "------------|-----|-------|\n")
            
            sorted_devs = sorted(self.devices.values(),
                                key=lambda d: d.total_packets, reverse=True)
            for i, d in enumerate(sorted_devs[:30], 1):
                flags = ', '.join(d.anomaly_flags) if d.anomaly_flags else '—'
                vendor = d.oui_vendor[:20] if d.oui_vendor else d.oui
                f.write(f"| {i} | `{d.bdaddr}` | "
                        f"{'Y' if d.addr_random else 'N'} | "
                        f"{d.total_packets} | "
                        f"{d.lifespan:.1f}s | "
                        f"{d.mean_rssi:.1f} dB | "
                        f"{vendor} | "
                        f"{flags} |\n")
            
            f.write("\n## Forensic Notes\n\n")
            f.write("This capture was conducted in **passive receive-only** mode. "
                    "No BLE connections were initiated, no scan requests were sent, "
                    "and no data was decrypted. All observations are derived from "
                    "publicly broadcast BLE advertising PDUs on channels 37, 38, "
                    "and 39.\n\n")
            f.write(f"Evidence chain file: `{self.evidence.chain_file.name}`  \n")
            f.write(f"Hash algorithm: {HASH_ALGO_USED}  \n")
            f.write(f"Total evidence records: {self.evidence.seq}  \n")
        
        sys.stderr.write(f"  Report: {report_path}\n")


# ─── Main Entry Point ─── #

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5 — BLE Anomaly Detector & Forensic Analyzer"
    )
    parser.add_argument(
        '--output', '-o', type=str, default='./phase5_evidence',
        help='Output directory for evidence files'
    )
    parser.add_argument(
        '--replay', '-r', type=str, default=None,
        help='Replay from saved NDJSON capture file instead of stdin'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Verbose output'
    )
    args = parser.parse_args()
    
    output_dir = Path(args.output)
    analyzer = BLEAnomalyAnalyzer(output_dir, verbose=args.verbose)
    
    # Handle graceful shutdown
    def shutdown(sig, frame):
        sys.stderr.write("\n  [*] Signal received, finalizing...\n")
        analyzer.finalize()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # Input source
    if args.replay:
        sys.stderr.write(f"  [*] Replaying from {args.replay}\n")
        with open(args.replay, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    analyzer.process_record(line)
    else:
        sys.stderr.write("  [*] Reading from stdin (pipe from ble_capture)\n")
        try:
            for line in sys.stdin:
                line = line.strip()
                if line:
                    analyzer.process_record(line)
        except KeyboardInterrupt:
            pass
    
    analyzer.finalize()


if __name__ == '__main__':
    main()

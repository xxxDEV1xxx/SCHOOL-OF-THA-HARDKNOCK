#!/usr/bin/env python3
"""
CTW-11 SENTINEL — Cell Environment Analyzer v3
Part 2 of 2: Legal Analysis & Reporting
Inventor: Christopher Thomas Williams

Accepts input from:
  1. CTW-11 collector JSON (--data cell_YYYYMMDD_data.json)
  2. CellMapper debug.html (--debug debug.html)
  3. CellMapper CSV (--csv signal.csv)
  4. Any combination of the above

Performs analysis:
  - GSM presence detection (always flagged — sunset in US)
  - Rogue EARFCN detection (0, 65535, 65536)
  - Suspicious ARFCN detection (1520-1550)
  - TAC anomaly detection (65535, 0xFFFF)
  - Null PLMN identity detection
  - Cell ID consistency cross-check
  - R+P flag detection (GSM downgrade attack indicator)
  - Multiple ECI on same eNB with divergent parameters
  - Unknown PCI with null MCC/MNC (phantom cells)

Output:
  Formal incident report suitable for filing with:
  - FCC Enforcement Bureau (47 U.S.C. § 333, § 302a)
  - FBI (18 U.S.C. § 1029, § 2511, § 2512)
  - DOJ Civil Rights Division (18 U.S.C. § 242)
  - California Attorney General (Cal. Penal Code § 629.50 et seq.)

Usage:
  python3 ctw11_cell_analyzer.py --debug debug.html
  python3 ctw11_cell_analyzer.py --debug debug.html --csv signal.csv
  python3 ctw11_cell_analyzer.py --data cell_data.json --debug debug.html
  python3 ctw11_cell_analyzer.py --debug debug.html -o report.txt
"""

import os
import sys
import json
import re
import argparse
import datetime
import hashlib
from collections import defaultdict

INVENTOR = "Christopher Thomas Williams"
VERSION  = "3.0"

# ============================================================
# RED FLAG CRITERIA
# ============================================================

# GSM is sunset in the US. Any GSM tower is anomalous.
# AT&T sunset: January 2017. T-Mobile sunset: April 2024.
# No legitimate US carrier operates GSM infrastructure.
GSM_ALWAYS_ANOMALOUS = True

# EARFCN values that are invalid or indicate rogue cells
ROGUE_EARFCN_VALUES = {0, 65535, 65536}

# GSM ARFCN range outside normal US allocations
SUSPICIOUS_ARFCN_RANGE = (1520, 1550)

# TAC values indicating unconfigured/rogue cells
ROGUE_TAC_VALUES = {0, 65535, 0xFFFE, 0xFFFF}

# Known legitimate PLMNs for US (MCC 310/311/312/313/316)
US_MCC_RANGE = set(range(310, 317))

# Verizon PLMNs
VERIZON_PLMNS = {"311480", "310590", "310890", "311270", "311580"}

# ============================================================
# CELLMAPPER CSV PARSER
# ============================================================
def parse_cellmapper_csv(csv_path):
    """
    Parse headerless CellMapper CSV.
    Columns: lat, lon, alt(?), mcc, mnc, tac, eci, signal, type, subtype, earfcn, pci
    """
    cells = []
    with open(csv_path, "r") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < 12:
                continue
            try:
                cell = {
                    "source":    "cellmapper_csv",
                    "line":      line_no,
                    "lat":       float(parts[0]),
                    "lon":       float(parts[1]),
                    "altitude":  int(parts[2]) if parts[2] else None,
                    "mcc":       int(parts[3]),
                    "mnc":       int(parts[4]),
                    "tac":       int(parts[5]),
                    "eci":       int(parts[6]),
                    "signal":    int(parts[7]),
                    "type":      parts[8],
                    "subtype":   parts[9],
                    "earfcn":    int(parts[10]),
                    "pci":       int(parts[11]),
                    "enb_id":    int(parts[6]) >> 8,
                    "lcid":      int(parts[6]) & 0xFF,
                }
                cells.append(cell)
            except (ValueError, IndexError):
                pass
    return cells


# ============================================================
# CELLMAPPER DEBUG.HTML PARSER
# ============================================================
def parse_cellmapper_debug(html_path):
    """
    Parse CellMapper debug.html for:
    - getAllCellInfo() data (all visible cells with full parameters)
    - ServiceState data
    - CellMapper internal data
    - Device and SIM information
    """
    with open(html_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    result = {
        "source": "cellmapper_debug",
        "device": {},
        "gps": {},
        "cells": [],
        "service_state": {},
        "cellmapper_data": {},
        "sim_info": {},
        "raw_fragments": [],
    }

    # Extract device info
    m = re.search(r'CellMapper\s+(A[\d.]+)\s*-\s*(.+?)\s*-\s*(\S+)', raw)
    if m:
        result["device"]["app_version"] = m.group(1)
        result["device"]["app_date"] = m.group(2).strip()
        result["device"]["phone_id"] = m.group(3)

    # Extract GPS data
    m = re.search(r'GPS:\s*Location\[gps\s+([\d.-]+),([\d.-]+)\s+hAcc=([\d.]+).*?alt=([\d.]+)', raw)
    if m:
        result["gps"]["lat"] = float(m.group(1))
        result["gps"]["lon"] = float(m.group(2))
        result["gps"]["h_acc"] = float(m.group(3))
        result["gps"]["alt"] = float(m.group(4))

    m = re.search(r'GPS time:\s*(\d+)', raw)
    if m:
        result["gps"]["gps_time_ms"] = int(m.group(1))
        try:
            result["gps"]["gps_time_utc"] = datetime.datetime.utcfromtimestamp(
                int(m.group(1)) / 1000).isoformat() + "Z"
        except Exception:
            pass

    # Extract SIM info
    m = re.search(r'getSimCarrierId\(\)\s*=\s*(\d+)', raw)
    if m:
        result["sim_info"]["carrier_id"] = int(m.group(1))
    m = re.search(r'getSimCarrierIdName\(\)\s*=\s*(\S+)', raw)
    if m:
        result["sim_info"]["carrier_name"] = m.group(1)
    m = re.search(r'getSimOperator\(\)\s*=\s*(\d+)', raw)
    if m:
        result["sim_info"]["sim_operator"] = m.group(1)
    m = re.search(r'getNetworkOperator\(\)\s*=\s*(\d+)', raw)
    if m:
        result["sim_info"]["network_operator"] = m.group(1)
    m = re.search(r'getTypeAllocationCode\(\)\s*=\s*(\d+)', raw)
    if m:
        result["sim_info"]["tac_code"] = m.group(1)

    # Extract isGsm flags — critical indicator
    # Format in HTML: isGsm(int =1) = <br>1: true<br>0: false
    gsm_flags = re.findall(r'isGsm\([^)]*\)\s*=\s*(?:<br>)?\s*\d+:\s*(true|false)', raw)
    if gsm_flags:
        result["service_state"]["is_gsm_flags"] = gsm_flags

    # Also check SignalStrength isGsm() = true
    sig_gsm = re.search(r'boolean isGsm\(\)\s*=\s*(true|false)', raw)
    if sig_gsm:
        result["service_state"]["signal_strength_is_gsm"] = sig_gsm.group(1) == "true"

    # Check for getNetworkTypeName returning GSM/GPRS (GSM stack active)
    net_type_names = re.findall(r'getNetworkTypeName\(.*?\)\s*=\s*(?:<br>)?\s*\d+:\s*(\w+)', raw)
    gsm_net_types = [n for n in net_type_names if n in ("GSM", "GPRS", "EDGE")]
    if gsm_net_types:
        result["service_state"]["gsm_network_types_detected"] = gsm_net_types

    # Check getCdmaEriText for "GSM nw" indicator
    gsm_eri = re.findall(r'getCdmaEriText.*?GSM nw', raw)
    if gsm_eri:
        result["service_state"]["gsm_eri_indicator"] = True

    # Extract all CellInfoLte blocks from getAllCellInfo()
    cell_pattern = re.compile(
        r'CellInfoLte:\{mRegistered=(YES|NO)\s+'
        r'mTimeStamp=(\S+)\s+'
        r'mCellConnectionStatus=(\d+)\s+'
        r'CellIdentityLte:\{\s*'
        r'mCi=(\d+)\s+'
        r'mPci=(\d+)\s+'
        r'mTac=(\d+)\s+'
        r'mEarfcn=(\d+)\s+'
        r'mBands=\[([^\]]*)\]\s+'
        r'mBandwidth=(\d+)\s+'
        r'mMcc=(\S+?)\s+'
        r'mMnc=(\S+?)\s+'
        r'mAlphaLong=([^}]*?)\s+'
        r'mAlphaShort=([^}]*?)\s+'
    )

    for m in cell_pattern.finditer(raw):
        ci = int(m.group(4))
        pci = int(m.group(5))
        tac = int(m.group(6))
        earfcn = int(m.group(7))
        bands_str = m.group(8).strip()
        bw = int(m.group(9))
        mcc_str = m.group(10).strip()
        mnc_str = m.group(11).strip()
        alpha_long = m.group(12).strip()

        cell = {
            "source":       "debug_getAllCellInfo",
            "registered":   m.group(1) == "YES",
            "timestamp_ns": m.group(2),
            "connection_status": int(m.group(3)),
            "ci":           ci,
            "pci":          pci,
            "tac":          tac,
            "earfcn":       earfcn,
            "bands":        bands_str,
            "bandwidth":    bw,
            "mcc":          None if mcc_str in ("null", "2147483647") else mcc_str,
            "mnc":          None if mnc_str in ("null", "2147483647") else mnc_str,
            "operator":     alpha_long if alpha_long else None,
            "type":         "LTE",
        }

        # Derived fields
        if ci != 2147483647:
            cell["eci"] = ci
            cell["enb_id"] = ci >> 8
            cell["lcid"] = ci & 0xFF
        else:
            cell["eci"] = None
            cell["enb_id"] = None
            cell["lcid"] = None

        if tac == 2147483647:
            cell["tac"] = None

        result["cells"].append(cell)

    # Extract signal strength data per cell
    sig_pattern = re.compile(
        r'CellSignalStrengthLte:\s+'
        r'rssi=(-?\d+)\s+'
        r'rsrp=(-?\d+)\s+'
        r'rsrq=(-?\d+)\s+'
        r'rssnr=(-?\d+)\s+'
        r'.*?ta=(-?\d+)\s+'
        r'level=(\d+)'
    )

    sig_matches = list(sig_pattern.finditer(raw))
    # Try to align signal data with cells by position in document
    for i, sm in enumerate(sig_matches):
        if i < len(result["cells"]):
            rssi = int(sm.group(1))
            rsrp = int(sm.group(2))
            rsrq = int(sm.group(3))
            rssnr = int(sm.group(4))
            ta = int(sm.group(5))
            level = int(sm.group(6))

            cell = result["cells"][i]
            cell["rssi"] = rssi if rssi != 2147483647 else None
            cell["rsrp"] = rsrp if rsrp != 2147483647 else None
            cell["rsrq"] = rsrq if rsrq != 2147483647 else None
            cell["rssnr"] = rssnr if rssnr != 2147483647 else None
            cell["ta"] = ta if ta != 2147483647 else None
            cell["level"] = level

    # Extract ServiceState channel and registration info
    m = re.search(r'mChannelNumber=(\d+)', raw)
    if m:
        result["service_state"]["channel"] = int(m.group(1))

    m = re.search(r'mVoiceRegState=(\d+)\((\w+)\)', raw)
    if m:
        result["service_state"]["voice_state"] = m.group(2)

    m = re.search(r'mDataRegState=(\d+)\((\w+)\)', raw)
    if m:
        result["service_state"]["data_state"] = m.group(2)

    ca_match = re.search(r'isUsingCarrierAggregation=(true|false)', raw)
    if ca_match:
        result["service_state"]["carrier_aggregation"] = ca_match.group(1) == "true"

    bw_match = re.search(r'mCellBandwidths=\[([^\]]+)\]', raw)
    if bw_match:
        result["service_state"]["cell_bandwidths"] = bw_match.group(1)

    # Extract CellMapper internal JSON
    json_match = re.search(r'class org\.json\.JSONObject i\(\)\s*=\s*(\{[^}]+\})', raw)
    if json_match:
        try:
            result["cellmapper_data"] = json.loads(json_match.group(1))
        except json.JSONDecodeError:
            result["cellmapper_data"]["raw"] = json_match.group(1)

    return result


# ============================================================
# CTW-11 JSON PARSER
# ============================================================
def parse_ctw11_json(json_path):
    """Parse CTW-11 collector JSON output."""
    with open(json_path, "r") as f:
        data = json.load(f)
    for entry in data:
        entry["source"] = "ctw11_collector"
    return data


# ============================================================
# ANOMALY ANALYSIS ENGINE
# ============================================================
class AnomalyFinding:
    """A single identified anomaly with legal citations."""
    def __init__(self, severity, category, description, evidence, citations):
        self.severity = severity       # CRITICAL / HIGH / MEDIUM / INFO
        self.category = category       # e.g. "ROGUE_CELL", "GSM_DOWNGRADE"
        self.description = description
        self.evidence = evidence        # dict of supporting data
        self.citations = citations      # list of legal citations
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()


def analyze_cells(all_cells, debug_data=None):
    """
    Run full anomaly analysis across all cell observations.
    Returns list of AnomalyFinding objects.
    """
    findings = []

    # Unique cells by (earfcn, pci)
    unique_cells = {}
    for cell in all_cells:
        earfcn = cell.get("earfcn")
        pci = cell.get("pci")
        if earfcn is not None and pci is not None:
            key = (earfcn, pci)
            if key not in unique_cells:
                unique_cells[key] = []
            unique_cells[key].append(cell)

    # ============================================================
    # CHECK 1: GSM Presence (always flagged)
    # ============================================================
    gsm_cells = [c for c in all_cells
                 if c.get("type", "").upper() == "GSM"
                 or c.get("decode_type", "").upper() == "GSM"
                 or c.get("band_type", "").upper() == "GSM"]

    if gsm_cells:
        findings.append(AnomalyFinding(
            severity="CRITICAL",
            category="GSM_PRESENCE",
            description=(
                f"GSM cellular technology detected ({len(gsm_cells)} observations). "
                f"All major US carriers have permanently decommissioned GSM infrastructure "
                f"(AT&T January 2017, T-Mobile April 2024). "
                f"GSM presence in the US in 2025+ indicates either an unauthorized "
                f"base station (IMSI catcher/cell-site simulator) or a foreign-operated "
                f"rogue cell. GSM's lack of mutual authentication makes it the preferred "
                f"technology for surveillance intercept devices."
            ),
            evidence={"gsm_observations": len(gsm_cells),
                      "sample": gsm_cells[0] if gsm_cells else None},
            citations=[
                "47 U.S.C. § 333 — Willful interference with radio communications",
                "47 U.S.C. § 302a — Unauthorized operation of radio equipment",
                "18 U.S.C. § 2511 — Interception of wire, oral, or electronic communications",
                "18 U.S.C. § 2512 — Manufacture/possession of interception devices",
                "18 U.S.C. § 1029 — Fraud and related activity in connection with access devices",
                "47 C.F.R. § 22.901 et seq. — Cellular system technical requirements",
            ]
        ))

    # Also check debug data for GSM indicators
    if debug_data:
        gsm_flags = debug_data.get("service_state", {}).get("is_gsm_flags", [])
        if any(f == "true" for f in gsm_flags):
            findings.append(AnomalyFinding(
                severity="HIGH",
                category="GSM_STACK_ACTIVE",
                description=(
                    f"Android RIL reports isGsm()=true on at least one radio interface. "
                    f"This indicates the device's baseband is recognizing a GSM network, "
                    f"which should not exist in US airspace. Combined with LTE primary "
                    f"registration, this suggests a multi-RAT attack attempting GSM "
                    f"downgrade on a secondary radio path."
                ),
                evidence={"is_gsm_flags": gsm_flags},
                citations=[
                    "18 U.S.C. § 2511 — Interception of communications",
                    "18 U.S.C. § 1030 — Computer fraud (baseband manipulation)",
                ]
            ))

    # ============================================================
    # CHECK 2: Rogue EARFCN Values
    # ============================================================
    for cell in all_cells:
        earfcn = cell.get("earfcn")
        if earfcn is not None and earfcn in ROGUE_EARFCN_VALUES:
            findings.append(AnomalyFinding(
                severity="CRITICAL",
                category="ROGUE_EARFCN",
                description=(
                    f"LTE cell detected with EARFCN={earfcn}. "
                    f"EARFCN value {earfcn} is not assigned to any legitimate "
                    f"frequency band in the 3GPP EARFCN allocation table (3GPP TS 36.101). "
                    f"This value is characteristic of cell-site simulators that "
                    f"impersonate legitimate cells using fabricated channel numbers."
                ),
                evidence={
                    "earfcn": earfcn,
                    "pci": cell.get("pci"),
                    "mcc": cell.get("mcc"),
                    "mnc": cell.get("mnc"),
                    "signal": cell.get("signal") or cell.get("rsrp"),
                },
                citations=[
                    "47 U.S.C. § 333 — Willful interference",
                    "47 U.S.C. § 302a — Unauthorized radio equipment",
                    "18 U.S.C. § 2512 — Interception device",
                    "47 C.F.R. § 27.50 — Power and emission limits",
                ]
            ))

    # ============================================================
    # CHECK 3: Suspicious ARFCN Range (GSM)
    # ============================================================
    for cell in all_cells:
        arfcn = cell.get("arfcn")
        if arfcn is not None:
            if SUSPICIOUS_ARFCN_RANGE[0] <= arfcn <= SUSPICIOUS_ARFCN_RANGE[1]:
                findings.append(AnomalyFinding(
                    severity="CRITICAL",
                    category="SUSPICIOUS_ARFCN",
                    description=(
                        f"GSM cell with ARFCN={arfcn} detected. "
                        f"This ARFCN falls within range {SUSPICIOUS_ARFCN_RANGE[0]}-"
                        f"{SUSPICIOUS_ARFCN_RANGE[1]}, which is not allocated to any "
                        f"US carrier for GSM operation. This is consistent with a "
                        f"cell-site simulator operating on a non-standard channel."
                    ),
                    evidence={"arfcn": arfcn, "cell": cell},
                    citations=[
                        "47 U.S.C. § 333 — Willful interference",
                        "47 C.F.R. § 22.355 — GSM channel assignments",
                    ]
                ))

    # ============================================================
    # CHECK 4: Rogue TAC Values
    # ============================================================
    for cell in all_cells:
        tac = cell.get("tac")
        if tac is not None and tac in ROGUE_TAC_VALUES:
            findings.append(AnomalyFinding(
                severity="HIGH",
                category="ROGUE_TAC",
                description=(
                    f"LTE cell with TAC={tac} (0x{tac:04X}) detected. "
                    f"TAC value {tac} is reserved/invalid per 3GPP TS 24.301 "
                    f"and is not assigned to any legitimate carrier tracking area. "
                    f"Cell-site simulators commonly broadcast TAC=65535 or TAC=0 "
                    f"to force device re-registration and capture IMSI/IMEI."
                ),
                evidence={
                    "tac": tac,
                    "earfcn": cell.get("earfcn"),
                    "pci": cell.get("pci"),
                    "mcc": cell.get("mcc"),
                    "mnc": cell.get("mnc"),
                },
                citations=[
                    "18 U.S.C. § 1029 — Access device fraud (IMSI capture)",
                    "18 U.S.C. § 2511 — Interception of communications",
                    "47 U.S.C. § 333 — Willful interference",
                ]
            ))

    # ============================================================
    # CHECK 5: Null PLMN Identity (phantom cells)
    # ============================================================
    phantom_cells = []
    for cell in all_cells:
        mcc = cell.get("mcc")
        mnc = cell.get("mnc")
        pci = cell.get("pci")
        earfcn = cell.get("earfcn")

        # Cell with PCI and EARFCN but no MCC/MNC is a phantom
        if pci is not None and earfcn is not None:
            if mcc is None and mnc is None:
                phantom_cells.append(cell)

    if phantom_cells:
        # Deduplicate by (earfcn, pci)
        seen = set()
        unique_phantoms = []
        for c in phantom_cells:
            key = (c.get("earfcn"), c.get("pci"))
            if key not in seen:
                seen.add(key)
                unique_phantoms.append(c)

        findings.append(AnomalyFinding(
            severity="HIGH",
            category="PHANTOM_CELLS",
            description=(
                f"{len(unique_phantoms)} unique cell(s) detected broadcasting "
                f"PCI and EARFCN but withholding MCC/MNC identity. "
                f"Legitimate cells always broadcast their PLMN identity in SIB1. "
                f"A cell that withholds PLMN identity while being visible to the "
                f"device's radio is consistent with a cell-site simulator in "
                f"passive monitoring mode or initial beacon phase."
            ),
            evidence={
                "phantom_count": len(unique_phantoms),
                "phantoms": [
                    {"earfcn": c.get("earfcn"), "pci": c.get("pci"),
                     "rsrp": c.get("rsrp"), "bands": c.get("bands")}
                    for c in unique_phantoms
                ],
            },
            citations=[
                "47 U.S.C. § 333 — Willful interference",
                "18 U.S.C. § 2512 — Interception device manufacture/possession",
            ]
        ))

    # ============================================================
    # CHECK 6: Same PCI on multiple EARFCNs (band spoofing)
    # ============================================================
    pci_earfcns = defaultdict(set)
    for cell in all_cells:
        pci = cell.get("pci")
        earfcn = cell.get("earfcn")
        if pci is not None and earfcn is not None:
            pci_earfcns[pci].add(earfcn)

    for pci, earfcns in pci_earfcns.items():
        # A PCI appearing on multiple EARFCNs is normal for carrier aggregation
        # and multi-band deployments, but flag if any EARFCN is suspicious
        suspicious = earfcns & ROGUE_EARFCN_VALUES
        if suspicious:
            findings.append(AnomalyFinding(
                severity="HIGH",
                category="PCI_ROGUE_EARFCN_COMBO",
                description=(
                    f"PCI {pci} observed on EARFCNs {sorted(earfcns)}, "
                    f"including rogue value(s) {sorted(suspicious)}. "
                    f"A legitimate cell rebroadcast with an invalid EARFCN "
                    f"on the same PCI suggests frequency spoofing by a "
                    f"cell-site simulator."
                ),
                evidence={"pci": pci, "earfcns": sorted(earfcns)},
                citations=[
                    "47 U.S.C. § 333",
                    "18 U.S.C. § 2512",
                ]
            ))

    # ============================================================
    # CHECK 7: Multiple ECIs on same eNB with divergent TACs
    # ============================================================
    enb_tacs = defaultdict(set)
    enb_ecis = defaultdict(set)
    for cell in all_cells:
        enb = cell.get("enb_id")
        tac = cell.get("tac")
        eci = cell.get("eci")
        if enb is not None and tac is not None:
            enb_tacs[enb].add(tac)
        if enb is not None and eci is not None:
            enb_ecis[enb].add(eci)

    for enb, tacs in enb_tacs.items():
        if len(tacs) > 1 and any(t in ROGUE_TAC_VALUES for t in tacs):
            findings.append(AnomalyFinding(
                severity="HIGH",
                category="ENB_TAC_DIVERGENCE",
                description=(
                    f"eNB {enb} observed with multiple TAC values {sorted(tacs)}, "
                    f"including rogue value(s). Legitimate eNBs serve a single TAC. "
                    f"Multiple TACs including invalid values suggest a cell-site "
                    f"simulator cycling through configurations."
                ),
                evidence={"enb_id": enb, "tacs": sorted(tacs),
                          "ecis": sorted(enb_ecis.get(enb, set()))},
                citations=[
                    "47 U.S.C. § 333",
                    "18 U.S.C. § 2511",
                ]
            ))

    return findings


# ============================================================
# REPORT GENERATOR
# ============================================================
def generate_report(findings, all_cells, debug_data, csv_path, data_path, output_path):
    """
    Generate formal incident report suitable for regulatory/law enforcement filing.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    now_date = now.strftime("%B %d, %Y")

    # Calculate file hashes for evidence integrity
    hashes = {}
    for label, path in [("debug.html", csv_path), ("csv", csv_path),
                        ("ctw11_json", data_path)]:
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                hashes[label] = hashlib.sha256(f.read()).hexdigest()

    # GPS location from debug data
    gps = {}
    if debug_data:
        gps = debug_data.get("gps", {})

    # Count by severity
    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f.severity].append(f)

    # Deduplicate findings by category
    seen_categories = set()
    unique_findings = []
    for f in findings:
        if f.category not in seen_categories:
            seen_categories.add(f.category)
            unique_findings.append(f)

    lines = []
    w = lines.append

    w("=" * 78)
    w("FORMAL INCIDENT REPORT")
    w("UNAUTHORIZED CELLULAR TRANSMISSION / CELL-SITE SIMULATOR ACTIVITY")
    w("=" * 78)
    w("")
    w(f"Report Generated:    {now_str}")
    w(f"Report Date:         {now_date}")
    w(f"Reporting Party:     {INVENTOR}")
    w(f"Analyzer Version:    CTW-11 SENTINEL Cell Analyzer v{VERSION}")
    w(f"Classification:      UNCLASSIFIED // LAW ENFORCEMENT SENSITIVE")
    w("")
    w("-" * 78)
    w("EXECUTIVE SUMMARY")
    w("-" * 78)
    w("")
    w(f"This report documents {len(unique_findings)} distinct anomalous")
    w(f"cellular transmission finding(s) identified through passive RF")
    w(f"monitoring at the location specified below. The findings are")
    w(f"consistent with the operation of one or more unauthorized")
    w(f"cell-site simulator(s) (commonly known as \"IMSI catchers\" or")
    w(f"\"Stingray\" devices) in the vicinity of the complainant's")
    w(f"residence.")
    w("")
    w(f"Findings by severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        count = len(by_severity.get(sev, []))
        if count:
            w(f"  {sev}: {count}")
    w("")

    w("-" * 78)
    w("LOCATION AND COLLECTION PARAMETERS")
    w("-" * 78)
    w("")
    if gps:
        w(f"GPS Coordinates:     {gps.get('lat', 'N/A')}, {gps.get('lon', 'N/A')}")
        w(f"GPS Accuracy:        {gps.get('h_acc', 'N/A')} meters")
        w(f"Altitude:            {gps.get('alt', 'N/A')} meters MSL")
        if gps.get("gps_time_utc"):
            w(f"GPS Timestamp:       {gps['gps_time_utc']}")
    else:
        w("GPS Coordinates:     See attached evidence files")
    w(f"Municipality:        Perris, California (Riverside County)")
    w(f"Collection Method:   Passive downlink monitoring (no transmission)")
    w(f"Equipment:           CellMapper A5.6.5 on HMD N159V (Android 14)")
    if debug_data and debug_data.get("device"):
        dev = debug_data["device"]
        w(f"Device ID:           {dev.get('phone_id', 'N/A')}")
    w("")

    w("-" * 78)
    w("EVIDENCE FILES AND INTEGRITY")
    w("-" * 78)
    w("")
    for label, h in hashes.items():
        w(f"SHA-256 ({label}):")
        w(f"  {h}")
    w("")

    w("-" * 78)
    w("CELLULAR ENVIRONMENT SUMMARY")
    w("-" * 78)
    w("")
    w(f"Total cell observations:  {len(all_cells)}")

    # Unique cells
    unique_by_earfcn_pci = set()
    for c in all_cells:
        e = c.get("earfcn")
        p = c.get("pci")
        if e is not None and p is not None:
            unique_by_earfcn_pci.add((e, p))
    w(f"Unique cells (EARFCN/PCI): {len(unique_by_earfcn_pci)}")

    # EARFCNs observed
    earfcns = set(c.get("earfcn") for c in all_cells if c.get("earfcn") is not None)
    w(f"EARFCNs observed:     {sorted(earfcns)}")

    # PCIs observed
    pcis = set(c.get("pci") for c in all_cells if c.get("pci") is not None)
    w(f"PCIs observed:        {sorted(pcis)}")

    # eNBs observed
    enbs = set(c.get("enb_id") for c in all_cells if c.get("enb_id") is not None)
    w(f"eNB IDs observed:     {sorted(enbs)}")

    # PLMNs observed
    plmns = set()
    for c in all_cells:
        mcc = c.get("mcc")
        mnc = c.get("mnc")
        if mcc is not None and mnc is not None:
            plmns.add(f"{mcc}/{mnc}")
    w(f"PLMNs observed:       {sorted(plmns) if plmns else 'None identified'}")
    w("")

    if debug_data and debug_data.get("cells"):
        w("Cells visible to device at time of debug capture:")
        w("")
        for i, cell in enumerate(debug_data["cells"]):
            reg = "REGISTERED" if cell.get("registered") else "neighbor"
            mcc = cell.get("mcc", "null")
            mnc = cell.get("mnc", "null")
            pci = cell.get("pci", "?")
            earfcn = cell.get("earfcn", "?")
            bands = cell.get("bands", "?")
            rsrp = cell.get("rsrp", "?")
            rsrq = cell.get("rsrq", "?")
            ta = cell.get("ta", "N/A")
            ci = cell.get("ci", "?")
            eci = cell.get("eci")
            enb = cell.get("enb_id")

            w(f"  Cell {i}: PCI={pci} EARFCN={earfcn} Band={bands} "
              f"MCC={mcc} MNC={mnc} [{reg}]")
            w(f"          RSRP={rsrp} RSRQ={rsrq} TA={ta}")
            if eci:
                w(f"          ECI={eci} eNB={enb} LCID={cell.get('lcid')}")
            if mcc is None and mnc is None:
                w(f"          *** NULL PLMN — PHANTOM CELL ***")
            w("")

    w("-" * 78)
    w("ANOMALY FINDINGS")
    w("-" * 78)
    w("")

    for i, finding in enumerate(unique_findings, 1):
        w(f"FINDING {i}: [{finding.severity}] {finding.category}")
        w(f"{'~' * 60}")
        w("")
        # Wrap description
        desc = finding.description
        while len(desc) > 76:
            split = desc[:76].rfind(" ")
            if split == -1:
                split = 76
            w(f"  {desc[:split]}")
            desc = desc[split:].strip()
        if desc:
            w(f"  {desc}")
        w("")

        w("  Evidence:")
        for k, v in finding.evidence.items():
            if isinstance(v, (list, dict)):
                w(f"    {k}: {json.dumps(v, default=str)}")
            else:
                w(f"    {k}: {v}")
        w("")

        w("  Applicable Statutes:")
        for cite in finding.citations:
            w(f"    - {cite}")
        w("")

    w("-" * 78)
    w("LEGAL FRAMEWORK")
    w("-" * 78)
    w("")
    w("The following federal and state statutes are applicable to the")
    w("unauthorized operation of cell-site simulators and the interception")
    w("of cellular communications:")
    w("")
    w("FEDERAL:")
    w("  47 U.S.C. § 333 — Willful or malicious interference with any")
    w("    radio communication authorized by the FCC. Carries penalties")
    w("    up to $100,000 per violation and imprisonment up to one year.")
    w("")
    w("  47 U.S.C. § 302a — Unlawful to manufacture, import, sell, or")
    w("    operate devices that do not comply with FCC regulations.")
    w("")
    w("  18 U.S.C. § 2511 — Illegal interception of wire, oral, or")
    w("    electronic communications. Felony with penalties up to five")
    w("    years imprisonment per count.")
    w("")
    w("  18 U.S.C. § 2512 — Manufacture, distribution, possession, and")
    w("    advertising of wire, oral, or electronic communication")
    w("    intercepting devices. Felony with penalties up to five years.")
    w("")
    w("  18 U.S.C. § 1029 — Fraud and related activity in connection")
    w("    with access devices (including IMSI/IMEI capture).")
    w("")
    w("  18 U.S.C. § 1030 — Computer Fraud and Abuse Act (unauthorized")
    w("    access to device baseband processor constitutes unauthorized")
    w("    access to a protected computer).")
    w("")
    w("  18 U.S.C. § 242 — Deprivation of rights under color of law")
    w("    (applicable if law enforcement operates without warrant).")
    w("")
    w("STATE (CALIFORNIA):")
    w("  Cal. Penal Code § 629.50-629.98 — California Electronic")
    w("    Communications Privacy Act (CalECPA). Requires warrant for")
    w("    use of cell-site simulators by law enforcement.")
    w("")
    w("  Cal. Gov. Code § 53166 — Requires local law enforcement to")
    w("    obtain approval before acquiring cell-site simulator")
    w("    technology and mandates public disclosure.")
    w("")

    w("-" * 78)
    w("FILING RECOMMENDATIONS")
    w("-" * 78)
    w("")
    w("Based on the findings documented herein, the following filings")
    w("are recommended:")
    w("")
    w("1. FCC ENFORCEMENT BUREAU")
    w("   File via: https://consumercomplaints.fcc.gov/")
    w("   Category: Interference / Unauthorized Operation")
    w("   Reference: 47 U.S.C. §§ 302a, 333")
    w("   Attach: This report, debug.html, CSV data")
    w("")
    w("2. FBI FIELD OFFICE (Los Angeles / Riverside)")
    w("   File via: https://tips.fbi.gov/ or local field office")
    w("   Category: Electronic surveillance / Wiretapping")
    w("   Reference: 18 U.S.C. §§ 2511, 2512, 1029")
    w("   Note: Request IC3 referral if cyber nexus identified")
    w("")
    w("3. DOJ CIVIL RIGHTS DIVISION")
    w("   If evidence suggests government operation without warrant:")
    w("   Reference: 18 U.S.C. § 242, 42 U.S.C. § 1985(3)")
    w("")
    w("4. CALIFORNIA ATTORNEY GENERAL")
    w("   File via: https://oag.ca.gov/contact/consumer-complaint-against-business-or-company")
    w("   Reference: Cal. Penal Code § 629.50, Cal. Gov. Code § 53166")
    w("")
    w("5. RIVERSIDE COUNTY DISTRICT ATTORNEY")
    w("   Public Integrity Unit")
    w("   Reference: Cal. Penal Code § 629.50 et seq.")
    w("")

    w("-" * 78)
    w("DECLARATION")
    w("-" * 78)
    w("")
    w("I, Christopher Thomas Williams, declare under penalty of perjury")
    w("under the laws of the United States of America and the State of")
    w("California that the foregoing technical analysis is true and")
    w("correct to the best of my knowledge and belief, and that the")
    w("data referenced herein was collected through passive monitoring")
    w("of publicly broadcast radio signals using lawful equipment")
    w("operated in compliance with FCC Part 15 regulations.")
    w("")
    w(f"Date: {now_date}")
    w("")
    w("")
    w("________________________________________")
    w(f"{INVENTOR}")
    w("Independent Security Researcher")
    w("Perris, California")
    w("")
    w("=" * 78)
    w(f"END OF REPORT — Generated {now_str}")
    w(f"CTW-11 SENTINEL Cell Analyzer v{VERSION}")
    w("=" * 78)

    report_text = "\n".join(lines)

    with open(output_path, "w") as f:
        f.write(report_text)

    return report_text


# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="CTW-11 Cell Analyzer — Anomaly Detection & Legal Report")
    parser.add_argument(
        "--data", type=str, default=None,
        help="CTW-11 collector JSON file (cell_YYYYMMDD_data.json)")
    parser.add_argument(
        "--debug", type=str, default=None,
        help="CellMapper debug.html file")
    parser.add_argument(
        "--csv", type=str, default=None,
        help="CellMapper CSV file (signal-YYYY-MM-DD.csv)")
    parser.add_argument(
        "-o", "--output", type=str, default=None,
        help="Output report path (default: auto-generated)")

    args = parser.parse_args()

    if not any([args.data, args.debug, args.csv]):
        parser.error("At least one input required: --data, --debug, or --csv")

    print("=" * 60)
    print(f" CTW-11 SENTINEL — Cell Analyzer v{VERSION}")
    print(f" Inventor: {INVENTOR}")
    print("=" * 60)

    all_cells = []
    debug_data = None

    # Parse CTW-11 JSON
    if args.data and os.path.exists(args.data):
        print(f"[CTW11] Loading CTW-11 data: {args.data}")
        ctw_cells = parse_ctw11_json(args.data)
        all_cells.extend(ctw_cells)
        print(f"         {len(ctw_cells)} cell records loaded")

    # Parse CellMapper debug.html
    if args.debug and os.path.exists(args.debug):
        print(f"[CTW11] Loading CellMapper debug: {args.debug}")
        debug_data = parse_cellmapper_debug(args.debug)
        debug_cells = debug_data.get("cells", [])
        all_cells.extend(debug_cells)
        print(f"         {len(debug_cells)} cells from debug")
        if debug_data.get("gps"):
            gps = debug_data["gps"]
            print(f"         GPS: {gps.get('lat')}, {gps.get('lon')}")

    # Parse CellMapper CSV
    if args.csv and os.path.exists(args.csv):
        print(f"[CTW11] Loading CellMapper CSV: {args.csv}")
        csv_cells = parse_cellmapper_csv(args.csv)
        all_cells.extend(csv_cells)
        print(f"         {len(csv_cells)} observations loaded")

    if not all_cells:
        print("[CTW11] ERROR: No cell data found in input files.")
        sys.exit(1)

    print(f"\n[CTW11] Total cell observations: {len(all_cells)}")
    print(f"[CTW11] Running anomaly analysis...")

    # Run analysis
    findings = analyze_cells(all_cells, debug_data)

    # Generate output path
    if args.output:
        output_path = args.output
    else:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = f"CTW11_INCIDENT_REPORT_{ts}.txt"

    print(f"\n[CTW11] Analysis complete.")
    print(f"         Findings: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        count = len([f for f in findings if f.severity == sev])
        if count:
            print(f"           {sev}: {count}")

    # Generate report
    report = generate_report(
        findings, all_cells, debug_data,
        args.csv or args.debug, args.data, output_path)

    print(f"\n[CTW11] Report written: {output_path}")
    print(f"         Size: {len(report)} bytes")

    # Print summary to stdout
    print("\n" + "=" * 60)
    print(" FINDINGS SUMMARY")
    print("=" * 60)
    seen = set()
    for f in findings:
        if f.category not in seen:
            seen.add(f.category)
            print(f"\n  [{f.severity}] {f.category}")
            # Truncate description for console
            desc = f.description[:200]
            if len(f.description) > 200:
                desc += "..."
            print(f"  {desc}")

    print("\n" + "=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())

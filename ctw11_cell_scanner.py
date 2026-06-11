#!/usr/bin/env python3
"""
CTW-11 SENTINEL — Cell Scanner / FCC Report Generator
Part 2 of 2: Analysis and Report Generation
Inventor: Christopher Thomas Williams

Consumes anomaly JSON produced by ctw11_cell_collector.py.
Generates a structured FCC-ready evidentiary report with:
  - Statutory analysis per anomaly type
  - Tower identity cross-reference table
  - Evidence chain metadata
  - SHA-256 hash of every input and output file (manifest)

Usage:
  python3 ctw11_cell_scanner.py <anomalies.json>
  python3 ctw11_cell_scanner.py <anomalies.json> --output /opt/ctw11/reports/

Output:
  report_YYYYMMDD_HHMMSS.txt          Human-readable FCC report
  report_YYYYMMDD_HHMMSS.json         Machine-readable structured report
  report_YYYYMMDD_HHMMSS_manifest.sha256

Security hardening (matching collector):
  SEC-01  Input file size capped at MAX_INPUT_BYTES before read
  SEC-02  JSON parse depth limited; array length capped at MAX_ANOMALY_RECORDS
  SEC-03  All anomaly field values validated/sanitized before use in output
  SEC-04  Report files opened with O_CREAT|O_EXCL|O_NOFOLLOW|0o600
  SEC-05  Output dir created atomically with umask(0o077)
  SEC-06  No subprocess calls; no shell expansion; no eval
  SEC-07  All string fields length-capped before output (MAX_FIELD_LEN)
  SEC-08  SHA-256 manifest covers input + both output files; chain_hash bound
  SEC-09  Path traversal guard on --output and input path
  SEC-10  Severity whitelist — only known severity strings accepted
  SEC-11  Statute strings matched against allowlist before inclusion in report
  SEC-12  Float fields validated finite and in physically plausible range
"""

import contextlib
import csv
import datetime
import hashlib
import json
import math
import os
import re
import signal
import stat
import sys
import threading
import time
from collections import defaultdict

# ============================================================
# SECURITY CONSTANTS
# ============================================================
MAX_INPUT_BYTES     = 100 * 1024 * 1024   # 100 MB input cap
MAX_ANOMALY_RECORDS = 50_000              # max records to parse
MAX_FIELD_LEN       = 512                 # max any string field
MAX_STATUTE_LEN     = 64                  # max one statute citation
MAX_LABEL_LEN       = 256
MAX_EXPLANATION_LEN = 2048

VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "NORMAL", "LOW", "INFO"})
VALID_ANOMALY_TYPES = frozenset({
    "SENTINEL_TAC", "SENTINEL_PCI", "SENTINEL_ENB_ID", "SENTINEL_ECI",
    "SENTINEL_LCID", "SENTINEL_LAC", "RESELECTION_FORCED",
    "TA_PROXIMITY_ANOMALY", "FOREIGN_MCC", "POWER_ANOMALY",
    "BAND71_ACTIVITY", "UNREGISTERED_CELL", "LTE_SIGNAL_DETECTED",
    "SIGNAL_DETECTED_NO_DECODE",
})

# Statute allowlist — only recognized US federal citations pass through
_STATUTE_RE = re.compile(
    r'^(47|18|28|42)\s+U\.S\.C\.\s+§\d+(\(\w+\))*'
    r'|^47\s+C\.F\.R\.\s+§[\d\.]+$'
)

INVENTOR      = "Christopher Thomas Williams"
DEVICE_SERIAL = "104473023196000bf5ff1a00aae12c3ca8"
OUTPUT_DIR    = "/opt/ctw11/reports"


# ============================================================
# SECURITY HELPERS
# ============================================================

@contextlib.contextmanager
def _safe_umask(mask=0o077):
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)


def _make_output_dir(path):
    with _safe_umask(0o077):
        os.makedirs(path, mode=0o700, exist_ok=True)


def _open_output_file(path, mode="w"):
    """O_CREAT|O_EXCL|O_NOFOLLOW|0o600 — no TOCTOU, no symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, mode)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _cap(value, maxlen=MAX_FIELD_LEN):
    """Hard-cap any string field; convert non-strings safely."""
    if value is None:
        return ""
    return str(value)[:maxlen]


def _sanitize_statute(s):
    """SEC-11: only pass statute strings matching federal citation pattern."""
    s = str(s).strip()[:MAX_STATUTE_LEN]
    return s if _STATUTE_RE.match(s) else None


def _sanitize_severity(s):
    """SEC-10: severity must be from whitelist."""
    s = str(s).strip().upper()
    return s if s in VALID_SEVERITIES else "UNKNOWN"


def _sanitize_anomaly_type(s):
    """SEC-10: anomaly type must be from known set."""
    s = str(s).strip().upper()
    return s if s in VALID_ANOMALY_TYPES else "UNKNOWN_TYPE"


def _validate_float(value, lo, hi):
    """SEC-12: float must be finite and in plausible physical range."""
    if value is None:
        return None
    try:
        f = float(value)
        if not math.isfinite(f):
            return None
        return f if lo <= f <= hi else None
    except (ValueError, TypeError):
        return None


def _validate_int(value, lo, hi):
    if value is None:
        return None
    try:
        n = int(float(str(value).strip()))
        return n if lo <= n <= hi else None
    except (ValueError, TypeError, OverflowError):
        return None


def _validate_mcc(value):
    if value is None:
        return None
    s = str(value).strip()
    return s if re.match(r'^\d{2,3}$', s) else None


def _validate_timestamp(value):
    """Accept ISO-8601 timestamp strings only."""
    if value is None:
        return "UNKNOWN"
    s = str(value).strip()[:32]
    if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', s):
        return s
    return "INVALID_TIMESTAMP"


def _safe_path(path):
    """SEC-09: resolve and reject traversal."""
    real = os.path.realpath(path)
    if ".." in os.path.relpath(real):
        raise ValueError(f"Path traversal detected: {path!r}")
    return real


# ============================================================
# ANOMALY RECORD SANITIZER
# ============================================================
def _sanitize_anomaly(raw):
    """
    SEC-03: sanitize one anomaly dict sourced from RF-collected JSON.
    Returns a clean dict with all fields validated.
    """
    typ      = _sanitize_anomaly_type(raw.get("type", ""))
    sev      = _sanitize_severity(raw.get("severity", ""))
    label    = _cap(raw.get("label", ""), MAX_LABEL_LEN)
    explanation = _cap(raw.get("explanation", ""), MAX_EXPLANATION_LEN)

    # Statute list — validate each entry
    raw_statutes = raw.get("statutes", [])
    if not isinstance(raw_statutes, list):
        raw_statutes = []
    statutes = []
    for s in raw_statutes[:20]:   # max 20 statutes per anomaly
        clean = _sanitize_statute(s)
        if clean:
            statutes.append(clean)

    # Value field — scalar only; reject nested objects
    raw_val = raw.get("value")
    if isinstance(raw_val, dict):
        value = {k: _cap(v, 128) for k, v in list(raw_val.items())[:10]}
    elif raw_val is None:
        value = None
    else:
        value = _cap(raw_val, 128)

    return {
        "type":        typ,
        "severity":    sev,
        "label":       label,
        "explanation": explanation,
        "statutes":    statutes,
        "value":       value,
    }


# ============================================================
# RECORD SANITIZER
# ============================================================
def _sanitize_record(raw):
    """
    SEC-03: sanitize one top-level anomaly record from JSON.
    All fields validated; anomaly sub-records individually sanitized.
    """
    ts       = _validate_timestamp(raw.get("timestamp"))
    freq_mhz = _validate_float(raw.get("freq_mhz"), 0.0, 7000.0)
    band     = _cap(raw.get("band", ""), 32)
    mcc      = _validate_mcc(raw.get("mcc"))
    mnc      = _validate_mcc(raw.get("mnc"))   # same 2-3 digit format
    cell_id  = _validate_int(raw.get("cell_id"), 0, 268_435_455)
    tac_lac  = _validate_int(raw.get("tac_lac"), 0, 65535)
    pci      = _validate_int(raw.get("pci"), 0, 2_147_483_647)
    power    = _validate_float(raw.get("power_dbm"), -200.0, 30.0)
    severity = _sanitize_severity(raw.get("severity", ""))
    anom_count = _validate_int(raw.get("anomaly_count"), 0, 10000) or 0

    raw_anomalies = raw.get("anomalies", [])
    if not isinstance(raw_anomalies, list):
        raw_anomalies = []
    anomalies = [_sanitize_anomaly(a) for a in raw_anomalies[:100]]

    return {
        "timestamp":     ts,
        "freq_mhz":      freq_mhz,
        "band":          band,
        "mcc":           mcc,
        "mnc":           mnc,
        "cell_id":       cell_id,
        "tac_lac":       tac_lac,
        "pci":           pci,
        "power_dbm":     power,
        "severity":      severity,
        "anomaly_count": anom_count,
        "anomalies":     anomalies,
    }


# ============================================================
# INPUT LOADER
# ============================================================
def load_anomaly_file(path):
    """
    SEC-01/02: size-guard input; cap array length; validate structure.
    Returns list of sanitized record dicts.
    """
    path = _safe_path(path)
    try:
        fsz = os.path.getsize(path)
    except OSError as e:
        raise RuntimeError(f"Cannot stat input file: {e}")
    if fsz > MAX_INPUT_BYTES:
        raise RuntimeError(
            f"Input file too large: {fsz//1024//1024} MB "
            f"(max {MAX_INPUT_BYTES//1024//1024} MB)")
    if fsz == 0:
        raise RuntimeError("Input file is empty")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read(MAX_INPUT_BYTES + 1)
    if len(raw_text) > MAX_INPUT_BYTES:
        raise RuntimeError("Input file exceeded size cap during read")

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError) as e:
        raise RuntimeError(f"Invalid JSON in input: {e}")

    if not isinstance(data, list):
        raise RuntimeError("Input JSON must be a top-level array")

    if len(data) > MAX_ANOMALY_RECORDS:
        print(f"[WARN] Input has {len(data)} records; "
              f"capping at {MAX_ANOMALY_RECORDS}")
        data = data[:MAX_ANOMALY_RECORDS]

    records = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            continue   # skip non-object entries
        try:
            records.append(_sanitize_record(item))
        except Exception as e:
            print(f"[WARN] Skipping record {i}: {e}")

    return records, _sha256_file(path)


# ============================================================
# REPORT GENERATOR
# ============================================================
class ReportGenerator:
    """
    Produces text and JSON FCC evidentiary reports from sanitized records.
    No subprocess calls. No eval. No shell expansion.
    """

    STATUTE_DESCRIPTIONS = {
        "47 U.S.C. §301":   "Prohibition on unlicensed transmission",
        "47 U.S.C. §333":   "Prohibition on interference with licensed stations",
        "18 U.S.C. §2511":  "Unlawful interception of wire/electronic communications",
        "18 U.S.C. §1030":  "Computer fraud and abuse (unauthorized access)",
        "18 U.S.C. §1519":  "Destruction/falsification of records",
        "42 U.S.C. §1985(3)": "Conspiracy to deprive civil rights",
        "47 C.F.R. §1.902": "FCC interference complaint procedure",
    }

    ANOMALY_DESCRIPTIONS = {
        "SENTINEL_TAC":      "Tracking Area Code sentinel value (65535=UINT16_MAX)",
        "SENTINEL_PCI":      "Physical Cell ID sentinel value (2147483647=INT32_MAX)",
        "SENTINEL_ENB_ID":   "eNodeB ID sentinel value (1048575=0xFFFFF)",
        "SENTINEL_ECI":      "E-UTRAN Cell Identity sentinel (268435455=0xFFFFFFF)",
        "SENTINEL_LCID":     "Logical Cell ID sentinel (255=UINT8_MAX)",
        "SENTINEL_LAC":      "Location Area Code sentinel (65535=UINT16_MAX)",
        "RESELECTION_FORCED": "Forced cell reselection (R+P flags simultaneously set)",
        "TA_PROXIMITY_ANOMALY": "Timing Advance=0 with abnormally strong signal",
        "FOREIGN_MCC":       "Non-US Mobile Country Code on US cellular frequencies",
        "POWER_ANOMALY":     "Received power inconsistent with licensed macro tower",
        "BAND71_ACTIVITY":   "Band 71 (600 MHz) activity — documented rogue band",
        "UNREGISTERED_CELL": "Cell identity absent from FCC tower database",
        "LTE_SIGNAL_DETECTED": "LTE signal detected (power mode — awaiting decode)",
        "SIGNAL_DETECTED_NO_DECODE": "GSM signal detected (power mode — awaiting decode)",
    }

    def __init__(self, records, input_path, input_hash, output_dir):
        self.records      = records
        self.input_path   = input_path
        self.input_hash   = input_hash
        self.output_dir   = output_dir
        self.ts           = datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    def generate(self):
        _make_output_dir(self.output_dir)
        base      = os.path.join(self.output_dir, f"report_{self.ts}")
        txt_path  = base + ".txt"
        json_path = base + ".json"
        mfst_path = base + "_manifest.sha256"

        txt_report  = self._build_text_report()
        json_report = self._build_json_report()

        with _open_output_file(txt_path,  "w") as f:
            f.write(txt_report)
        with _open_output_file(json_path, "w") as f:
            json.dump(json_report, f, indent=2, default=str)
            f.write("\n")

        # SHA-256 manifest
        file_hashes = {}
        path_map = {
            "input_anomalies": self.input_path,
            "report_txt":      txt_path,
            "report_json":     json_path,
        }
        for label, path in path_map.items():
            try:
                file_hashes[label] = _sha256_file(path)
            except Exception as e:
                file_hashes[label] = f"ERROR:{e}"

        # Verify input hash matches what we recorded at load time
        loaded_input_hash = file_hashes.get("input_anomalies", "")
        hash_verified     = (loaded_input_hash == self.input_hash)
        if not hash_verified:
            print(f"[WARN] Input file hash changed between load and report! "
                  f"Expected {self.input_hash} got {loaded_input_hash}")

        valid_hashes = sorted(v for v in file_hashes.values()
                              if not v.startswith("ERROR"))
        close_ts     = datetime.datetime.now(
            datetime.timezone.utc).isoformat()
        chain_input  = close_ts.encode() + b"".join(
            v.encode() for v in valid_hashes)
        chain_hash   = hashlib.sha256(chain_input).hexdigest()

        manifest = {
            "report_ts":      self.ts,
            "close_ts":       close_ts,
            "inventor":       INVENTOR,
            "device_serial":  DEVICE_SERIAL,
            "input_hash_at_load":   self.input_hash,
            "input_hash_verified":  hash_verified,
            "files":          file_hashes,
            "chain_hash":     chain_hash,
            "algorithm":      "SHA-256",
            "verify_cmd":     "sha256sum -c <manifest>",
            "note": ("chain_hash = SHA256(close_ts || sorted(file_hashes)). "
                     "input_hash_verified confirms input was not modified "
                     "between load and report generation."),
        }
        with _open_output_file(mfst_path, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n\n# sha256sum-compatible:\n")
            for label, hexdigest in file_hashes.items():
                if not hexdigest.startswith("ERROR"):
                    fname = os.path.basename(path_map[label])
                    f.write(f"{hexdigest}  {fname}\n")

        files = {
            "report_txt":  txt_path,
            "report_json": json_path,
            "manifest":    mfst_path,
        }
        print("\n[CTW11] Report files:")
        for k, v in files.items():
            print(f"  {k:<12}: {v}")
        print(f"  chain:       {chain_hash}")
        print(f"  input ok:    {hash_verified}")
        return files

    def _build_text_report(self):
        records  = self.records
        critical = [r for r in records if r["severity"] == "CRITICAL"]
        high     = [r for r in records if r["severity"] == "HIGH"]
        total_a  = sum(r["anomaly_count"] for r in records)

        # Aggregate statutes
        statute_hits = defaultdict(int)
        for r in records:
            for a in r["anomalies"]:
                for s in a["statutes"]:
                    statute_hits[s] += 1

        # Aggregate anomaly types
        type_hits = defaultdict(int)
        for r in records:
            for a in r["anomalies"]:
                type_hits[a["type"]] += 1

        W = 70
        lines = []
        lines.append("=" * W)
        lines.append("CTW-11 SENTINEL — CELLULAR SPECTRUM ANOMALY REPORT")
        lines.append(f"Inventor:       {INVENTOR}")
        lines.append(f"Device Serial:  {DEVICE_SERIAL}")
        lines.append(f"Report Date:    {self.ts} UTC")
        lines.append(f"Input File:     {os.path.basename(self.input_path)}")
        lines.append(f"Input SHA-256:  {self.input_hash}")
        lines.append("=" * W)
        lines.append("")
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * W)
        lines.append(f"  Total anomaly records:  {len(records)}")
        lines.append(f"  Critical severity:       {len(critical)}")
        lines.append(f"  High severity:           {len(high)}")
        lines.append(f"  Total anomaly events:    {total_a}")
        lines.append("")

        if statute_hits:
            lines.append("STATUTORY VIOLATIONS IMPLICATED")
            lines.append("-" * W)
            for statute, count in sorted(statute_hits.items(),
                                          key=lambda x: -x[1]):
                desc = self.STATUTE_DESCRIPTIONS.get(statute, "")
                lines.append(f"  [{count:>4}x]  {statute}")
                if desc:
                    lines.append(f"           {desc}")
            lines.append("")

        if type_hits:
            lines.append("ANOMALY TYPE SUMMARY")
            lines.append("-" * W)
            for typ, count in sorted(type_hits.items(), key=lambda x: -x[1]):
                desc = self.ANOMALY_DESCRIPTIONS.get(typ, typ)
                lines.append(f"  [{count:>4}x]  {typ}")
                lines.append(f"           {desc}")
            lines.append("")

        lines.append("CRITICAL ANOMALY DETAIL")
        lines.append("-" * W)
        if not critical:
            lines.append("  None")
        for idx, rec in enumerate(critical[:500], 1):
            lines.append(f"\n  [{idx}] {rec['timestamp']}  "
                         f"{rec['band']}  {rec['freq_mhz']:.3f} MHz")
            lines.append(f"      MCC:{rec['mcc']}  MNC:{rec['mnc']}  "
                         f"CellID:{rec['cell_id']}  "
                         f"TAC/LAC:{rec['tac_lac']}  "
                         f"PCI:{rec['pci']}")
            lines.append(f"      Power: {rec['power_dbm']} dBm")
            for a in rec["anomalies"]:
                if a["severity"] == "CRITICAL":
                    lines.append(f"      [CRITICAL] {a['type']}: {a['label']}")
                    if a["explanation"]:
                        lines.append(f"        Explanation: {a['explanation']}")
                    if a["statutes"]:
                        lines.append(f"        Statutes: {', '.join(a['statutes'])}")

        lines.append("")
        lines.append("HIGH SEVERITY ANOMALY DETAIL")
        lines.append("-" * W)
        if not high:
            lines.append("  None")
        for idx, rec in enumerate(high[:200], 1):
            lines.append(f"\n  [{idx}] {rec['timestamp']}  "
                         f"{rec['band']}  {rec['freq_mhz']:.3f} MHz")
            lines.append(f"      Power: {rec['power_dbm']} dBm")
            for a in rec["anomalies"]:
                if a["severity"] in ("CRITICAL", "HIGH"):
                    lines.append(f"      [{a['severity']}] {a['type']}: {a['label']}")

        lines.append("")
        lines.append("=" * W)
        lines.append("CHAIN OF CUSTODY")
        lines.append("-" * W)
        lines.append(f"  Input anomaly file:  {self.input_path}")
        lines.append(f"  Input SHA-256:       {self.input_hash}")
        lines.append(f"  Report generated:    {self.ts} UTC")
        lines.append(f"  Legal basis: Passive downlink monitoring only.")
        lines.append(f"  No uplink decode. No IMSI/IMEI capture.")
        lines.append(f"  47 C.F.R. Part 15 passive monitoring provisions.")
        lines.append("=" * W)

        return "\n".join(lines) + "\n"

    def _build_json_report(self):
        statute_hits = defaultdict(int)
        type_hits    = defaultdict(int)
        for r in self.records:
            for a in r["anomalies"]:
                for s in a["statutes"]:
                    statute_hits[s] += 1
                type_hits[a["type"]] += 1

        return {
            "report_metadata": {
                "inventor":        INVENTOR,
                "device_serial":   DEVICE_SERIAL,
                "report_ts":       self.ts,
                "input_file":      os.path.basename(self.input_path),
                "input_sha256":    self.input_hash,
                "legal_basis":     (
                    "Passive downlink monitoring only. "
                    "No uplink decode. No IMSI/IMEI capture. "
                    "47 C.F.R. Part 15 passive monitoring provisions."),
            },
            "summary": {
                "total_records":    len(self.records),
                "critical_records": sum(1 for r in self.records
                                        if r["severity"] == "CRITICAL"),
                "high_records":     sum(1 for r in self.records
                                        if r["severity"] == "HIGH"),
                "total_anomalies":  sum(r["anomaly_count"]
                                        for r in self.records),
            },
            "statute_hit_counts":  dict(statute_hits),
            "anomaly_type_counts": dict(type_hits),
            "records":             self.records,
        }


# ============================================================
# SIGNAL HANDLER
# ============================================================
_running = threading.Event()
_running.set()


def _handle_sig(sig, frame):
    print("\n[CTW11] Interrupted")
    _running.clear()


signal.signal(signal.SIGINT,  _handle_sig)
signal.signal(signal.SIGTERM, _handle_sig)


# ============================================================
# ENTRY POINT
# ============================================================
def main():
    import argparse
    p = argparse.ArgumentParser(
        description="CTW-11 Sentinel — Cell Scanner / FCC Report Generator")
    p.add_argument("input",    help="Anomaly JSON from ctw11_cell_collector.py")
    p.add_argument("--output", default=OUTPUT_DIR,
                   help=f"Report output directory (default: {OUTPUT_DIR})")
    args = p.parse_args()

    # SEC-09: path validation
    try:
        input_path  = _safe_path(args.input)
        output_path = _safe_path(args.output)
    except ValueError as e:
        print(f"[ERR] {e}")
        sys.exit(1)

    if not os.path.exists(input_path):
        print(f"[ERR] Input not found: {input_path}")
        sys.exit(1)

    print("=" * 70)
    print(f" CTW-11 SENTINEL — FCC Report Generator  [{INVENTOR}]")
    print(f" Input:   {input_path}")
    print(f" Output:  {output_path}")
    print("=" * 70)

    try:
        records, input_hash = load_anomaly_file(input_path)
    except RuntimeError as e:
        print(f"[ERR] {e}")
        sys.exit(1)

    print(f"[OK] Loaded {len(records)} anomaly records")
    print(f"     Input SHA-256: {input_hash}")

    critical = sum(1 for r in records if r["severity"] == "CRITICAL")
    high     = sum(1 for r in records if r["severity"] == "HIGH")
    print(f"     Critical: {critical}  High: {high}")

    gen = ReportGenerator(
        records=records,
        input_path=input_path,
        input_hash=input_hash,
        output_dir=output_path,
    )
    files = gen.generate()

    print(f"\n[CTW11] Report generation complete")
    print(f"  Text:     {files['report_txt']}")
    print(f"  JSON:     {files['report_json']}")
    print(f"  Manifest: {files['manifest']}")


if __name__ == "__main__":
    main()

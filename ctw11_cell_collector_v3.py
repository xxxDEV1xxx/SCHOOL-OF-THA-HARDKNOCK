#!/usr/bin/env python3
"""
CTW-11 SENTINEL — Cellular Data Collector v3
Part 1 of 2: Raw Data Capture (UPGRADED)
Inventor: Christopher Thomas Williams

Changes from v2:
  - GSM technology is ALWAYS flagged as anomalous (deprecated in US)
  - EARFCN=0 or EARFCN=65535/65536 flagged (invalid/rogue indicators)
  - ARFCN 1520-1550 range flagged (suspicious GSM channel allocation)
  - TX explicitly disabled on PlutoSDR during all scan phases
  - All flags written to raw data — interpretation still in Part 2

Strategy:
  Phase 1 — Wideband energy sweep across all US cellular bands
             Find every carrier with signal above noise floor
             Record frequency, power, band identity

  Phase 2 — Lock onto each detected carrier
             Dwell and extract all available cell metadata:
             GSM: MCC, MNC, LAC, Cell ID, BSIC, TA, RXLEV, all SI messages
             LTE: eNB ID, TAC, PCI, LCID, ECI, PLMN, all SIB fields
             Record everything raw — no filtering, no flagging

  Output — Pure data files. All interpretation in Part 2.

Usage:
  python3 ctw11_cell_collector_v3.py
  python3 ctw11_cell_collector_v3.py --sweep-duration 180 --dwell 5
"""

import os
import sys
import json
import time
import datetime
import argparse
import threading
import subprocess
import signal
import math
from collections import defaultdict

# ============================================================
# DEPENDENCY IMPORTS
# ============================================================
try:
    import SoapySDR
    from SoapySDR import SOAPY_SDR_RX, SOAPY_SDR_TX, SOAPY_SDR_CF32
    SOAPY_OK = True
except ImportError:
    print("[ERR] SoapySDR required: apt install python3-soapysdr")
    sys.exit(1)

try:
    import numpy as np
except ImportError:
    print("[ERR] numpy required: apt install python3-numpy")
    sys.exit(1)

try:
    import scipy.signal as dsp
    SCIPY_OK = True
except ImportError:
    SCIPY_OK = False

try:
    for path in [
        "/usr/lib/python3/dist-packages/gnuradio/gsm",
        "/usr/local/lib/python3/dist-packages",
    ]:
        if path not in sys.path:
            sys.path.insert(0, path)
    import grgsm
    from gnuradio import gsm as gnuradio_gsm
    GRGSM_OK = True
except ImportError:
    GRGSM_OK = False

SRSRAN_OK = os.path.exists("/usr/bin/srsran_cell_search")

# ============================================================
# CONSTANTS
# ============================================================
INVENTOR   = "Christopher Thomas Williams"
OUTPUT_DIR = "/opt/ctw11/captures/gsm"

# AD9361 hardware limits
PLUTO_FREQ_MIN  = 70e6
PLUTO_FREQ_MAX  = 6e9
PLUTO_RATE_MIN  = 2083333
PLUTO_RATE_MAX  = 61440000
PLUTO_GAIN_MIN  = -3
PLUTO_GAIN_MAX  = 71
PLUTO_BW_MAX_RX = 56e6

# GSM parameters
GSM_SYMBOL_RATE = 270833
GSM_SAMPLE_RATE = int(GSM_SYMBOL_RATE * 4)   # ~1.083 MSPS

# LTE sample rates by bandwidth
LTE_BW_RATE = {
    1.4e6:  1920000,
    3e6:    3840000,
    5e6:    7680000,
    10e6:   15360000,
    15e6:   23040000,
    20e6:   30720000,
}

# ============================================================
# RED FLAG DEFINITIONS
# These are raw indicators — Part 2 does the legal analysis
# ============================================================

# GSM presence in the US is inherently anomalous:
# All major US carriers have sunset GSM (AT&T Jan 2017, T-Mobile Apr 2024)
# Any GSM tower detected in US airspace in 2025+ is a red flag
GSM_ALWAYS_FLAG = True

# LTE EARFCN values that indicate rogue/misconfigured cells
ROGUE_EARFCN = {0, 65535, 65536}

# GSM ARFCN range that is suspicious (outside normal US allocations)
SUSPICIOUS_ARFCN_LOW  = 1520
SUSPICIOUS_ARFCN_HIGH = 1550

# TAC values that indicate rogue cells
ROGUE_TAC = {0, 65535, 0xFFFE, 0xFFFF}

# All US cellular bands — downlink only (passive receive)
# Format: name, dl_low_hz, dl_high_hz, step_hz, type, bw_hz
US_BANDS = [
    # GSM — sunset in US, any detection is anomalous
    ("GSM850",       869.2e6,  893.8e6,  0.2e6,   "GSM", 0.2e6),
    ("GSM1900_PCS",  1930.0e6, 1990.0e6, 0.2e6,   "GSM", 0.2e6),
    # LTE
    ("LTE_B2_PCS",   1930.0e6, 1990.0e6, 5e6,     "LTE", 10e6),
    ("LTE_B4_AWS",   2110.0e6, 2155.0e6, 5e6,     "LTE", 10e6),
    ("LTE_B5_850",   869.0e6,  894.0e6,  5e6,     "LTE", 10e6),
    ("LTE_B12_700a", 729.0e6,  746.0e6,  5e6,     "LTE", 10e6),
    ("LTE_B13_700c", 746.0e6,  756.0e6,  5e6,     "LTE", 5e6),
    ("LTE_B17_700b", 734.0e6,  746.0e6,  5e6,     "LTE", 10e6),
    ("LTE_B25_PCS",  1930.0e6, 1995.0e6, 5e6,     "LTE", 10e6),
    ("LTE_B26_850",  859.0e6,  894.0e6,  5e6,     "LTE", 10e6),
    ("LTE_B66_AWS3", 2110.0e6, 2200.0e6, 10e6,    "LTE", 20e6),
    ("LTE_B71_600",  617.0e6,  652.0e6,  5e6,     "LTE", 10e6),
    # UMTS/WCDMA
    ("UMTS_850",     869.0e6,  894.0e6,  5e6,     "UMTS", 5e6),
    ("UMTS_1900",    1930.0e6, 1990.0e6, 5e6,     "UMTS", 5e6),
]

# ============================================================
# SIGNAL HANDLER
# ============================================================
_running = True

def handle_signal(sig, frame):
    global _running
    print("\n[CTW11] Stop signal received — finishing current scan...")
    _running = False

signal.signal(signal.SIGINT,  handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# ============================================================
# PLUTOSDR DEVICE — TX DISABLED
# ============================================================
class PlutoSDR:
    """
    PlutoSDR wrapper with TX explicitly killed.
    This device operates in RECEIVE-ONLY mode.
    No uplink transmission occurs at any point.
    """
    def __init__(self, gain=40):
        self.gain       = gain
        self.sdr        = None
        self.stream     = None
        self.cur_rate   = None
        self.cur_freq   = None
        self._lock      = threading.Lock()

    def open(self):
        devices = SoapySDR.Device.enumerate("driver=plutosdr")
        if not devices:
            raise RuntimeError(
                "No PlutoSDR found. Check OTG USB cable. "
                "Run: SoapySDRUtil --find")

        uri = devices[0]["uri"] if "uri" in devices[0] else "auto"
        print(f"[CTW11] PlutoSDR found: {uri}")

        self.sdr = SoapySDR.Device(devices[0])

        # =====================================================
        # CRITICAL: DISABLE TX CHAIN ENTIRELY
        # We are a passive receiver only. No transmission.
        # This ensures legal compliance under FCC Part 15
        # and prevents any accidental uplink activity.
        # =====================================================
        self._kill_tx()

        self._set_rate(GSM_SAMPLE_RATE)
        self.sdr.setGain(SOAPY_SDR_RX, 0, self.gain)
        self.sdr.setGainMode(SOAPY_SDR_RX, 0, False)
        print(f"[CTW11] Gain: {self.gain} dB | Rate: {self.cur_rate/1e6:.3f} MSPS")
        print(f"[CTW11] TX CHAIN: DISABLED (passive receive only)")
        return self

    def _kill_tx(self):
        """
        Aggressively disable the TX chain on AD9361.
        Multiple methods for defense in depth:
        1. Set TX gain to minimum (maximum attenuation)
        2. Set TX frequency to harmless out-of-band value
        3. Disable TX RF port via IIO if accessible
        """
        try:
            # Method 1: TX gain to minimum attenuation = max suppression
            # AD9361 TX gain range is -89.75 to 0 dB
            self.sdr.setGain(SOAPY_SDR_TX, 0, -89.75)
            print("[CTW11]   TX gain set to -89.75 dB (maximum attenuation)")
        except Exception as e:
            print(f"[CTW11]   TX gain suppression: {e}")

        try:
            # Method 2: Tune TX to a harmless frequency (DC, out of any band)
            self.sdr.setFrequency(SOAPY_SDR_TX, 0, 70e6)
            print("[CTW11]   TX frequency parked at 70 MHz (out of band)")
        except Exception as e:
            print(f"[CTW11]   TX frequency park: {e}")

        try:
            # Method 3: Set TX bandwidth to minimum
            self.sdr.setBandwidth(SOAPY_SDR_TX, 0, 200000)
            print("[CTW11]   TX bandwidth minimized to 200 kHz")
        except Exception as e:
            print(f"[CTW11]   TX bandwidth minimize: {e}")

        try:
            # Method 4: IIO direct — disable TX RF port
            # This uses the Pluto's IIO subsystem directly
            import subprocess
            subprocess.run(
                ["iio_attr", "-d", "ad9361-phy",
                 "out_voltage0_rf_port_select", "OFF"],
                capture_output=True, timeout=3)
            print("[CTW11]   TX RF port disabled via IIO")
        except Exception:
            pass  # IIO tools may not be available

    def _set_rate(self, rate):
        rate = int(max(PLUTO_RATE_MIN, min(rate, PLUTO_RATE_MAX)))
        if rate != self.cur_rate:
            self.sdr.setSampleRate(SOAPY_SDR_RX, 0, rate)
            bw = min(rate * 0.8, PLUTO_BW_MAX_RX)
            self.sdr.setBandwidth(SOAPY_SDR_RX, 0, bw)
            self.cur_rate = rate
            self._stop_stream()

    def _start_stream(self):
        if self.stream is None:
            self.stream = self.sdr.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32)
            self.sdr.activateStream(self.stream)

    def _stop_stream(self):
        if self.stream:
            self.sdr.deactivateStream(self.stream)
            self.sdr.closeStream(self.stream)
            self.stream = None

    def tune(self, freq_hz, rate=None):
        with self._lock:
            if rate:
                self._set_rate(rate)
            self.sdr.setFrequency(SOAPY_SDR_RX, 0, freq_hz)
            self.cur_freq = freq_hz
            time.sleep(0.05)  # PLL settling

    def read(self, num_samples):
        with self._lock:
            self._start_stream()
            buf = np.zeros(num_samples, dtype=np.complex64)
            got = 0
            while got < num_samples and _running:
                want = num_samples - got
                sr = self.sdr.readStream(
                    self.stream, [buf[got:]], want,
                    timeoutUs=2000000)
                if sr.ret < 0:
                    break
                got += sr.ret
            return buf[:got]

    def close(self):
        self._stop_stream()
        # Re-kill TX on close as safety measure
        if self.sdr:
            try:
                self.sdr.setGain(SOAPY_SDR_TX, 0, -89.75)
            except Exception:
                pass
        self.sdr = None
        print("[CTW11] PlutoSDR closed (TX remained disabled)")

    def __enter__(self):
        return self.open()

    def __exit__(self, *a):
        self.close()

# ============================================================
# POWER MEASUREMENT
# ============================================================
def power_dbm(samples):
    if len(samples) == 0:
        return -140.0
    p = float(np.mean(np.abs(samples) ** 2))
    return 10 * math.log10(p + 1e-20) - 30.0

def noise_floor_dbm(samples, percentile=10):
    block = 256
    n = len(samples) // block
    if n == 0:
        return power_dbm(samples)
    powers = [power_dbm(samples[i*block:(i+1)*block]) for i in range(n)]
    powers.sort()
    cutoff = max(1, int(len(powers) * percentile / 100))
    return float(np.mean(powers[:cutoff]))

def psd_peak_dbm(samples, rate, center_freq):
    nfft = min(4096, len(samples))
    if nfft < 64:
        return []
    window = np.blackman(nfft)
    spectrum = np.abs(np.fft.fftshift(
        np.fft.fft(samples[:nfft] * window))) ** 2
    freqs = center_freq + np.fft.fftshift(
        np.fft.fftfreq(nfft, 1.0/rate))
    psd_db = 10 * np.log10(spectrum + 1e-20) - 30.0
    return list(zip(freqs.tolist(), psd_db.tolist()))


# ============================================================
# RED FLAG TAGGING (raw indicators only)
# ============================================================
def tag_red_flags(entry):
    """
    Attach raw anomaly flags to a carrier/cell entry.
    These are factual observations — not legal conclusions.
    Part 2 (the scanner/analyzer) performs legal interpretation.
    """
    flags = []

    band_type = entry.get("band_type") or entry.get("decode_type", "")

    # FLAG: Any GSM presence in US airspace
    if band_type == "GSM" and GSM_ALWAYS_FLAG:
        flags.append("GSM_PRESENCE_US_SUNSET")

    # FLAG: EARFCN = 0 (invalid for any real cell)
    earfcn = entry.get("earfcn")
    if earfcn is not None and earfcn in ROGUE_EARFCN:
        flags.append(f"ROGUE_EARFCN_{earfcn}")

    # FLAG: ARFCN in suspicious range 1520-1550
    arfcn = entry.get("arfcn")
    if arfcn is not None:
        if SUSPICIOUS_ARFCN_LOW <= arfcn <= SUSPICIOUS_ARFCN_HIGH:
            flags.append(f"SUSPICIOUS_ARFCN_{arfcn}")

    # FLAG: TAC = 65535 or 0 (rogue cell indicator)
    tac = entry.get("tac")
    if tac is not None and tac in ROGUE_TAC:
        flags.append(f"ROGUE_TAC_{tac}")

    # FLAG: Null MCC/MNC (cell broadcasting without identity)
    mcc = entry.get("mcc")
    mnc = entry.get("mnc")
    if mcc is None and mnc is None and band_type in ("GSM", "LTE"):
        # Only flag if we attempted decode and got nothing
        if entry.get("grgsm_available") or entry.get("srsran_available"):
            flags.append("NULL_PLMN_IDENTITY")

    # FLAG: R+P registration flags (GSM downgrade attack indicator)
    rp = entry.get("rp_flags")
    if rp is not None:
        flags.append("RP_FLAGS_PRESENT")

    entry["red_flags"] = flags
    return entry


# ============================================================
# PHASE 1 — WIDEBAND SWEEP
# ============================================================
def sweep_band(pluto, band_name, dl_low, dl_high,
               step, bw, band_type, sweep_gain,
               threshold_db_above_noise=10.0):
    active = []
    freq = dl_low
    sweep_rate = min(max(int(bw * 1.25), PLUTO_RATE_MIN), PLUTO_RATE_MAX)
    num_samples = int(sweep_rate * 0.3)

    while freq <= dl_high and _running:
        pluto.tune(freq, rate=sweep_rate)
        samples = pluto.read(num_samples)
        if len(samples) < 64:
            freq += step
            continue

        pwr  = power_dbm(samples)
        nf   = noise_floor_dbm(samples)
        snr  = pwr - nf

        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if snr >= threshold_db_above_noise:
            entry = {
                "freq_hz":       freq,
                "freq_mhz":      round(freq / 1e6, 4),
                "power_dbm":     round(pwr, 2),
                "noise_floor_dbm": round(nf, 2),
                "snr_db":        round(snr, 2),
                "band":          band_name,
                "band_type":     band_type,
                "bandwidth_hz":  bw,
                "timestamp":     ts,
            }
            # Tag red flags at sweep level
            entry = tag_red_flags(entry)

            active.append(entry)

            flag_str = ""
            if entry.get("red_flags"):
                flag_str = f"  *** RED FLAGS: {entry['red_flags']}"
            print(f"  [SIGNAL] {band_name} {freq/1e6:.3f} MHz  "
                  f"pwr={pwr:.1f} dBm  snr={snr:.1f} dB{flag_str}")
        else:
            print(f"  [quiet]  {band_name} {freq/1e6:.3f} MHz  "
                  f"pwr={pwr:.1f} dBm  snr={snr:.1f} dB", end="\r")

        freq += step

    return active


def run_sweep(pluto, sweep_duration_sec, sweep_gain):
    print(f"\n[CTW11] PHASE 1 — Wideband sweep ({sweep_duration_sec}s budget)")
    print(f"        Scanning {len(US_BANDS)} band segments...")
    print(f"        TX CHAIN: DISABLED (passive receive only)")
    print()

    all_active = []
    sweep_start = time.time()

    for band_name, dl_low, dl_high, step, band_type, bw in US_BANDS:
        if not _running:
            break
        elapsed = time.time() - sweep_start
        if elapsed >= sweep_duration_sec:
            print(f"\n[CTW11] Sweep time budget reached ({sweep_duration_sec}s)")
            break

        print(f"  Sweeping {band_name} "
              f"({dl_low/1e6:.1f}-{dl_high/1e6:.1f} MHz)...")
        active = sweep_band(
            pluto, band_name, dl_low, dl_high,
            step, bw, band_type, sweep_gain)
        all_active.extend(active)

    # Deduplicate by frequency (within 100 kHz)
    deduped = []
    seen_freqs = []
    for entry in sorted(all_active, key=lambda x: -x["snr_db"]):
        f = entry["freq_hz"]
        too_close = any(abs(f - sf) < 100e3 for sf in seen_freqs)
        if not too_close:
            deduped.append(entry)
            seen_freqs.append(f)

    # Summary of flags
    flagged = [e for e in deduped if e.get("red_flags")]
    print(f"\n[CTW11] Sweep complete. "
          f"Found {len(deduped)} active carriers "
          f"({len(all_active)} raw detections)")
    if flagged:
        print(f"[CTW11] *** {len(flagged)} carriers have RED FLAGS ***")
        for e in flagged:
            print(f"         {e['band']} {e['freq_mhz']} MHz: "
                  f"{e['red_flags']}")

    return deduped


# ============================================================
# GSM METADATA EXTRACTION
# ============================================================
def extract_gsm_metadata(pluto, freq_hz, dwell_sec):
    result = {
        "freq_hz":      freq_hz,
        "freq_mhz":     round(freq_hz / 1e6, 4),
        "decode_type":  "GSM",
        "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "raw_power_dbm": None,
        "noise_floor_dbm": None,
        "snr_db":       None,
        "grgsm_available": GRGSM_OK,
        "mcc":          None,
        "mnc":          None,
        "lac":          None,
        "cell_id":      None,
        "bsic":         None,
        "rxlev":        None,
        "ta":           None,
        "rp_flags":     None,
        "c1":           None,
        "c2":           None,
        "arfcn":        None,
        "bcch_freq":    None,
        "si_messages":  [],
        "raw_bursts":   [],
        "decode_errors": [],
    }

    try:
        pluto.tune(freq_hz, rate=GSM_SAMPLE_RATE)
        num_samples = int(GSM_SAMPLE_RATE * dwell_sec)
        samples = pluto.read(num_samples)

        result["raw_power_dbm"]    = round(power_dbm(samples), 2)
        result["noise_floor_dbm"]  = round(noise_floor_dbm(samples), 2)
        result["snr_db"]           = round(
            result["raw_power_dbm"] - result["noise_floor_dbm"], 2)

        if not GRGSM_OK:
            result["decode_errors"].append("gr-gsm not available")
            result = tag_red_flags(result)
            return result

        tmp = f"/tmp/ctw11_gsm_{int(time.time()*1000)}.cfile"
        samples.tofile(tmp)

        cmd = [
            "grgsm_decode",
            "--cfile", tmp,
            "--samp-rate", str(GSM_SAMPLE_RATE),
            "--fc", str(int(freq_hz)),
            "--print-json",
            "--bursts",
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15)
            stdout = proc.stdout
            stderr = proc.stderr

            if proc.returncode != 0 and stderr:
                result["decode_errors"].append(stderr[:200])

            for line in stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    msg = json.loads(line)
                    msg_type = msg.get("type", "")
                    result["si_messages"].append(msg)

                    if any(t in msg_type for t in
                           ["SI1", "SYSTEM_INFORMATION_TYPE_1"]):
                        result["mcc"]     = msg.get("mcc", result["mcc"])
                        result["mnc"]     = msg.get("mnc", result["mnc"])
                        result["lac"]     = msg.get("lac", result["lac"])
                        result["cell_id"] = msg.get("cell_id", result["cell_id"])
                        result["bsic"]    = msg.get("bsic", result["bsic"])
                        result["arfcn"]   = msg.get("arfcn", result["arfcn"])

                    if any(t in msg_type for t in
                           ["SI3", "SYSTEM_INFORMATION_TYPE_3"]):
                        result["mcc"]     = msg.get("mcc", result["mcc"])
                        result["mnc"]     = msg.get("mnc", result["mnc"])
                        result["lac"]     = msg.get("lac", result["lac"])
                        result["cell_id"] = msg.get("cell_id", result["cell_id"])
                        result["c1"]      = msg.get("c1",      result["c1"])
                        result["c2"]      = msg.get("c2",      result["c2"])

                    if "MEASUREMENT" in msg_type.upper():
                        result["rxlev"] = msg.get("rxlev", result["rxlev"])
                        result["ta"]    = msg.get("ta",    result["ta"])

                    if any(k in msg for k in
                           ["reselect", "path_loss", "rp", "RP"]):
                        result["rp_flags"] = msg

                    if "burst" in msg_type.lower() or "BURST" in msg_type:
                        result["raw_bursts"].append(msg)

                    for field in ["mcc","mnc","lac","cell_id","bsic",
                                  "rxlev","ta","arfcn","c1","c2"]:
                        if field in msg and result[field] is None:
                            result[field] = msg[field]

                except json.JSONDecodeError:
                    pass

        except subprocess.TimeoutExpired:
            result["decode_errors"].append("grgsm_decode timeout")
        except FileNotFoundError:
            result["decode_errors"].append("grgsm_decode not in PATH")
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    except Exception as e:
        result["decode_errors"].append(str(e))

    # Tag red flags on decoded metadata
    result = tag_red_flags(result)
    return result


# ============================================================
# LTE METADATA EXTRACTION
# ============================================================
def extract_lte_metadata(pluto, freq_hz, bw_hz, dwell_sec):
    rate = min(
        [v for k, v in LTE_BW_RATE.items() if k >= bw_hz],
        default=LTE_BW_RATE[20e6])

    result = {
        "freq_hz":       freq_hz,
        "freq_mhz":      round(freq_hz / 1e6, 4),
        "decode_type":   "LTE",
        "timestamp":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "raw_power_dbm": None,
        "noise_floor_dbm": None,
        "snr_db":        None,
        "srsran_available": SRSRAN_OK,
        "mcc":           None,
        "mnc":           None,
        "tac":           None,
        "tac_hex":       None,
        "enb_id":        None,
        "cell_id":       None,
        "eci":           None,
        "pci":           None,
        "lcid":          None,
        "earfcn":        None,
        "dl_bw":         None,
        "num_prb":       None,
        "rsrp":          None,
        "rsrq":          None,
        "rssi":          None,
        "sinr":          None,
        "plmn":          None,
        "sib1":          None,
        "sib2":          None,
        "sib3":          None,
        "sib4":          None,
        "all_sibs":      [],
        "raw_output":    "",
        "decode_errors": [],
    }

    try:
        pluto.tune(freq_hz, rate=rate)
        num_samples = int(rate * dwell_sec)
        samples = pluto.read(num_samples)

        result["raw_power_dbm"]   = round(power_dbm(samples), 2)
        result["noise_floor_dbm"] = round(noise_floor_dbm(samples), 2)
        result["snr_db"]          = round(
            result["raw_power_dbm"] - result["noise_floor_dbm"], 2)

        if not SRSRAN_OK:
            result["decode_errors"].append("srsran_cell_search not available")
            result = tag_red_flags(result)
            return result

        bw_mhz = int(bw_hz / 1e6)
        cmd = [
            "srsran_cell_search",
            "-f", str(int(freq_hz)),
            "-b", str(bw_mhz),
            "--duration", str(max(5, int(dwell_sec))),
        ]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=dwell_sec + 10)
            output = proc.stdout + proc.stderr
            result["raw_output"] = output

            lines = output.splitlines()
            for i, line in enumerate(lines):
                line_lower = line.lower()

                if "pci:" in line_lower or "physical cell id" in line_lower:
                    val = _extract_int(line)
                    if val is not None:
                        result["pci"] = val

                if "mcc:" in line_lower:
                    val = _extract_after(line, "MCC:")
                    if val:
                        result["mcc"] = val.strip().strip(",")
                if "mnc:" in line_lower:
                    val = _extract_after(line, "MNC:")
                    if val:
                        result["mnc"] = val.strip().strip(",")

                if "tac:" in line_lower:
                    val = _extract_after(line, "TAC:")
                    if val:
                        raw = val.strip().strip(",")
                        result["tac_hex"] = raw
                        try:
                            result["tac"] = int(raw, 16)
                        except ValueError:
                            try:
                                result["tac"] = int(raw)
                            except ValueError:
                                result["tac"] = raw

                if "cell id:" in line_lower or "eci:" in line_lower:
                    val = _extract_int(line)
                    if val is not None:
                        result["eci"] = val
                        result["cell_id"] = val
                        result["enb_id"] = val >> 8
                        result["lcid"]   = val & 0xFF

                if "earfcn:" in line_lower:
                    val = _extract_int(line)
                    if val is not None:
                        result["earfcn"] = val

                if "bandwidth:" in line_lower or "n_rb_dl:" in line_lower:
                    val = _extract_int(line)
                    if val is not None:
                        result["num_prb"] = val
                        result["dl_bw"]   = val * 0.18

                if "rsrp:" in line_lower:
                    val = _extract_float(line)
                    if val is not None:
                        result["rsrp"] = val
                if "rsrq:" in line_lower:
                    val = _extract_float(line)
                    if val is not None:
                        result["rsrq"] = val
                if "rssi:" in line_lower:
                    val = _extract_float(line)
                    if val is not None:
                        result["rssi"] = val
                if "sinr:" in line_lower or "snr:" in line_lower:
                    val = _extract_float(line)
                    if val is not None:
                        result["sinr"] = val

                if "plmn:" in line_lower:
                    val = _extract_after(line, "PLMN:")
                    if val:
                        result["plmn"] = val.strip()

                if "sib" in line_lower:
                    sib_block = "\n".join(
                        lines[i:min(i+10, len(lines))])
                    result["all_sibs"].append(sib_block)
                    sib_num = _extract_int(line)
                    if sib_num == 1:
                        result["sib1"] = sib_block
                    elif sib_num == 2:
                        result["sib2"] = sib_block
                    elif sib_num == 3:
                        result["sib3"] = sib_block
                    elif sib_num == 4:
                        result["sib4"] = sib_block

        except subprocess.TimeoutExpired:
            result["decode_errors"].append("srsran_cell_search timeout")
        except FileNotFoundError:
            result["decode_errors"].append("srsran_cell_search not found")

    except Exception as e:
        result["decode_errors"].append(str(e))

    # Tag red flags on decoded metadata
    result = tag_red_flags(result)
    return result


def extract_umts_metadata(pluto, freq_hz, bw_hz, dwell_sec):
    result = {
        "freq_hz":       freq_hz,
        "freq_mhz":      round(freq_hz / 1e6, 4),
        "decode_type":   "UMTS",
        "timestamp":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "raw_power_dbm": None,
        "noise_floor_dbm": None,
        "snr_db":        None,
        "psd_peaks":     [],
        "decode_errors": ["UMTS full decode requires CPICH correlator — power only"],
    }

    try:
        rate = int(5e6)
        pluto.tune(freq_hz, rate=rate)
        samples = pluto.read(int(rate * dwell_sec))

        result["raw_power_dbm"]   = round(power_dbm(samples), 2)
        result["noise_floor_dbm"] = round(noise_floor_dbm(samples), 2)
        result["snr_db"]          = round(
            result["raw_power_dbm"] - result["noise_floor_dbm"], 2)

        peaks = psd_peak_dbm(samples, rate, freq_hz)
        peaks_sorted = sorted(peaks, key=lambda x: -x[1])[:20]
        result["psd_peaks"] = [
            {"freq_hz": round(f, 0), "power_dbm": round(p, 2)}
            for f, p in peaks_sorted
        ]

    except Exception as e:
        result["decode_errors"].append(str(e))

    result = tag_red_flags(result)
    return result


# ============================================================
# PARSE HELPERS
# ============================================================
def _extract_int(line):
    import re
    m = re.search(r'[-+]?\d+', line.split(":")[-1])
    return int(m.group()) if m else None

def _extract_float(line):
    import re
    m = re.search(r'[-+]?\d+\.?\d*', line.split(":")[-1])
    return float(m.group()) if m else None

def _extract_after(line, key):
    idx = line.upper().find(key.upper())
    if idx == -1:
        return None
    rest = line[idx + len(key):].strip()
    return rest.split()[0] if rest else None


# ============================================================
# PHASE 2 — TARGETED DECODE
# ============================================================
def run_targeted_decode(pluto, active_carriers, dwell_sec):
    print(f"\n[CTW11] PHASE 2 — Targeted decode "
          f"({len(active_carriers)} carriers, {dwell_sec}s dwell each)")
    print(f"        TX CHAIN: DISABLED (passive receive only)")

    results = []

    for i, carrier in enumerate(active_carriers):
        if not _running:
            break

        freq_hz   = carrier["freq_hz"]
        band_type = carrier["band_type"]
        bw_hz     = carrier["bandwidth_hz"]
        band_name = carrier["band"]

        flag_str = ""
        if carrier.get("red_flags"):
            flag_str = f" *** {carrier['red_flags']}"

        print(f"\n  [{i+1}/{len(active_carriers)}] "
              f"{band_name} {freq_hz/1e6:.3f} MHz "
              f"({band_type}) "
              f"snr={carrier['snr_db']:.1f}dB{flag_str}")

        if band_type == "GSM":
            meta = extract_gsm_metadata(pluto, freq_hz, dwell_sec)
        elif band_type == "LTE":
            meta = extract_lte_metadata(pluto, freq_hz, bw_hz, dwell_sec)
        elif band_type == "UMTS":
            meta = extract_umts_metadata(pluto, freq_hz, bw_hz, dwell_sec)
        else:
            meta = {"freq_hz": freq_hz, "decode_type": "UNKNOWN"}
            meta = tag_red_flags(meta)

        meta["sweep_power_dbm"]      = carrier["power_dbm"]
        meta["sweep_noise_floor_dbm"]= carrier["noise_floor_dbm"]
        meta["sweep_snr_db"]         = carrier["snr_db"]
        meta["band"]                 = band_name
        meta["band_type"]            = band_type
        meta["bandwidth_hz"]         = bw_hz

        results.append(meta)

        for field in ["mcc","mnc","lac","tac","cell_id","eci",
                      "pci","enb_id","bsic","ta"]:
            val = meta.get(field)
            if val is not None:
                print(f"    {field}: {val}")

        if meta.get("red_flags"):
            print(f"    *** RED FLAGS: {meta['red_flags']}")

    return results


# ============================================================
# SESSION OUTPUT
# ============================================================
class Session:
    def __init__(self, output_dir, args):
        os.makedirs(output_dir, exist_ok=True)
        ts        = datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.ts   = ts
        base      = os.path.join(output_dir, f"cell_{ts}")
        self.sweep_path = base + "_sweep.json"
        self.data_path  = base + "_data.json"
        self.meta_path  = base + "_meta.txt"

        with open(self.meta_path, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("CTW-11 SENTINEL — Cell Collection Session v3\n")
            f.write(f"Inventor: {INVENTOR}\n")
            f.write(f"Session Start (UTC): {ts}\n")
            f.write(f"Sweep Duration: {args.sweep_duration}s\n")
            f.write(f"Dwell Per Carrier: {args.dwell}s\n")
            f.write(f"Sweep Gain: {args.sweep_gain} dB\n")
            f.write(f"Decode Gain: {args.decode_gain} dB\n")
            f.write(f"gr-gsm available: {GRGSM_OK}\n")
            f.write(f"srsRAN available: {SRSRAN_OK}\n")
            f.write(f"Sweep output: {self.sweep_path}\n")
            f.write(f"Data output: {self.data_path}\n")
            f.write("=" * 60 + "\n")
            f.write("LEGAL NOTICE:\n")
            f.write("  Passive downlink monitoring only.\n")
            f.write("  TX chain DISABLED on PlutoSDR during all phases.\n")
            f.write("  No uplink decode. No IMSI/IMEI capture.\n")
            f.write("  All channels are public broadcast.\n")
            f.write("  Red flags: GSM presence, EARFCN 0/65535/65536,\n")
            f.write("    ARFCN 1520-1550, TAC 65535, null PLMN.\n")
            f.write("=" * 60 + "\n")

    def save_sweep(self, active_carriers):
        with open(self.sweep_path, "w") as f:
            json.dump(active_carriers, f, indent=2)
        print(f"[CTW11] Sweep saved: {self.sweep_path}")

    def save_data(self, decoded_results):
        with open(self.data_path, "w") as f:
            json.dump(decoded_results, f, indent=2)
        print(f"[CTW11] Data saved: {self.data_path}")

    def finalize(self, active_count, decode_count):
        end_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(self.meta_path, "a") as f:
            f.write(f"\nSession End (UTC): {end_ts}\n")
            f.write(f"Active carriers found: {active_count}\n")
            f.write(f"Carriers decoded: {decode_count}\n")
        print(f"[CTW11] Metadata: {self.meta_path}")
        return {
            "sweep": self.sweep_path,
            "data":  self.data_path,
            "meta":  self.meta_path,
        }


# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="CTW-11 Cell Collector v3 — Sweep then Decode (TX Disabled)")
    parser.add_argument(
        "--sweep-duration", type=int, default=180,
        help="Phase 1 sweep budget in seconds (default: 180)")
    parser.add_argument(
        "--dwell", type=float, default=5.0,
        help="Phase 2 dwell per carrier in seconds (default: 5.0)")
    parser.add_argument(
        "--sweep-gain", type=float, default=50.0,
        help="RX gain for sweep phase, 0-71 dB (default: 50)")
    parser.add_argument(
        "--decode-gain", type=float, default=40.0,
        help="RX gain for decode phase, 0-71 dB (default: 40)")
    parser.add_argument(
        "--threshold", type=float, default=8.0,
        help="SNR threshold in dB for carrier detection (default: 8)")
    parser.add_argument(
        "--output", default=OUTPUT_DIR,
        help=f"Output directory (default: {OUTPUT_DIR})")
    parser.add_argument(
        "--continuous", action="store_true",
        help="Run sweep+decode cycles continuously until Ctrl+C")

    args = parser.parse_args()
    args.sweep_gain  = max(PLUTO_GAIN_MIN, min(args.sweep_gain,  PLUTO_GAIN_MAX))
    args.decode_gain = max(PLUTO_GAIN_MIN, min(args.decode_gain, PLUTO_GAIN_MAX))

    print("=" * 60)
    print(f" CTW-11 SENTINEL — Cell Collector v3")
    print(f" Inventor: {INVENTOR}")
    print(f" TX CHAIN: DISABLED (passive receive only)")
    print(f" gr-gsm:  {'YES' if GRGSM_OK else 'NO — power only'}")
    print(f" srsRAN:  {'YES' if SRSRAN_OK else 'NO — power only'}")
    print(f" Sweep:   {args.sweep_duration}s budget | threshold: {args.threshold} dB")
    print(f" Decode:  {args.dwell}s per carrier")
    print(f" Flags:   GSM=always, EARFCN={{0,65535,65536}}, "
          f"ARFCN 1520-1550, TAC 65535")
    print("=" * 60)

    cycle = 0
    while _running:
        cycle += 1
        if args.continuous:
            print(f"\n[CTW11] === CYCLE {cycle} ===")

        session = Session(args.output, args)

        with PlutoSDR(gain=args.sweep_gain) as pluto:
            active_carriers = run_sweep(
                pluto,
                sweep_duration_sec=args.sweep_duration,
                sweep_gain=args.sweep_gain)

        session.save_sweep(active_carriers)

        if not active_carriers:
            print("[CTW11] No active carriers found in sweep.")
            print("        Try increasing --sweep-gain or lowering --threshold")
            files = session.finalize(0, 0)
        else:
            with PlutoSDR(gain=args.decode_gain) as pluto:
                decoded = run_targeted_decode(
                    pluto, active_carriers, args.dwell)

            session.save_data(decoded)
            files = session.finalize(len(active_carriers), len(decoded))

            print(f"\n[CTW11] Collection complete.")
            print(f"        Carriers found:   {len(active_carriers)}")
            print(f"        Carriers decoded: {len(decoded)}")
            flagged = [d for d in decoded if d.get("red_flags")]
            if flagged:
                print(f"        *** RED-FLAGGED:  {len(flagged)} ***")

        print(f"\n[CTW11] Run analyzer:")
        print(f"  python3 ctw11_cell_analyzer.py {files['data']}")
        print(f"  python3 ctw11_cell_analyzer.py --debug debug.html")

        if not args.continuous or not _running:
            break

        print(f"\n[CTW11] Continuous mode — starting next cycle in 10s...")
        time.sleep(10)


if __name__ == "__main__":
    main()

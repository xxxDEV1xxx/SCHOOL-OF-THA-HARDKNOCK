#!/usr/bin/env python3
"""
fs5000_live.py — FS-5000 live monitor for headless RHEL 9
Renders dose rate in real time via:
  1. gnuplot → X11 window  (requires DISPLAY set, e.g. ssh -X or local Xorg)
  2. ASCII sparkline        (pure VT fallback, always available)
  3. CSV log               (always written)
  4. Spike/plateau detection (AnomalyEngine from fs5000_dump.py logic)

Usage:
  python3 fs5000_live.py --port /dev/ttyUSB0
  python3 fs5000_live.py --port /dev/ttyUSB0 --no-gnuplot   # ASCII only
  python3 fs5000_live.py --port /dev/ttyUSB0 --out /tmp/rad

Requirements (RHEL 9):
  dnf install gnuplot python3-pyserial
  # or: pip3 install pyserial --user

Live stream protocol note:
  The FS-5000 emits ASCII lines in either of two known formats:
    Format A (stream): DR:0.18uSv/h;D:58.1uSv;CPS:0001;CPM:000021;...
    Format B (framed): AA <len> 0E <data> <cs> 55  — binary frame, val * 0.01
  This script handles both. If Format B is seen, Format A parsing is skipped
  for that read cycle.

Made by: Christopher T. Williams
"""

import argparse
import csv
import datetime
import os
import select
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque

import serial
import serial.tools.list_ports

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CH340_VID = 0x1A86
CH340_PID = 0x7523
BAUD      = 115200
STAMP     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# Natural background band (µSv/h) — ICRP / EPA reference
BG_LOW  = 0.05
BG_HIGH = 0.35
# Spike threshold
SPIKE_THRESH = 1.0
SPIKE_END    = 0.35

# Gnuplot window refresh interval (seconds)
GNUPLOT_INTERVAL = 2.0

# How many samples to keep in rolling display window
DISPLAY_WINDOW = 300   # ~5 min at 1 Hz

# ---------------------------------------------------------------------------
# Port discovery
# ---------------------------------------------------------------------------

def find_port() -> str:
    for p in serial.tools.list_ports.comports():
        if p.vid == CH340_VID and p.pid == CH340_PID:
            print(f"[AUTO] FS-5000 on {p.device} [{p.description}]")
            return p.device
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("ERROR: No serial ports. Is the CH340 driver loaded? (modprobe ch341)")
        sys.exit(1)
    print("CH340 not auto-detected. Available ports:")
    for p in ports:
        print(f"  {p.device}  {p.description}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

def checksum(data: bytes) -> int:
    return sum(data) % 256

def make_packet(payload: bytes) -> bytes:
    hdr  = bytes([0xAA, len(payload) + 3])
    body = hdr + payload
    cs   = bytes([checksum(body)])
    return body + cs + bytes([0x55])

LIVE_START = make_packet(bytes([0x0E, 0x01]))
LIVE_STOP  = make_packet(bytes([0x0E, 0x00]))

# ---------------------------------------------------------------------------
# Live frame parser — handles both ASCII and binary frames in the rx buffer
# ---------------------------------------------------------------------------

class LiveParser:
    """
    Maintains a byte buffer across reads.
    Yields (unix_ts, dose_rate_uSvh) tuples as they are decoded.

    Binary frame: AA <len> 0E <data> <cs> 55
      data[0] == 0x06  → ACK, skip
      otherwise        → data[0:4] big-endian uint32 = val * 0.01 µSv/h
      (observed: AA 07 0E <4-byte-val> <cs> 55)

    ASCII stream: DR:0.18uSv/h;D:58.1uSv;CPS:...
    """

    def __init__(self):
        self._buf = bytearray()
        self._ascii_buf = ""

    def feed(self, data: bytes):
        self._buf.extend(data)
        samples = []
        # Try binary frames first
        samples.extend(self._parse_binary())
        if samples:
            # Clear ascii buf if we're getting binary
            self._ascii_buf = ""
            return samples
        # Fall back to ASCII
        samples.extend(self._parse_ascii())
        return samples

    def _parse_binary(self):
        samples = []
        buf = self._buf
        i = 0
        consumed = 0
        while i < len(buf):
            if buf[i] != 0xAA:
                i += 1
                continue
            if i + 1 >= len(buf):
                break
            length = buf[i + 1]
            end = i + 2 + length
            if end > len(buf):
                break   # incomplete frame — wait for more data
            frame = buf[i:end]
            payload = frame[2:-2]
            rx_cs   = frame[-2]
            tr      = frame[-1]
            if tr != 0x55:
                i += 1
                continue
            calc_cs = checksum(frame[:2 + len(payload)])
            if calc_cs != rx_cs:
                i += 1
                continue
            # Valid frame — check if it's a live data frame
            if len(payload) >= 1 and payload[0] == 0x0E:
                # Live data frame
                data_bytes = payload[1:]
                if len(data_bytes) >= 4 and data_bytes[0] != 0x06:
                    val_raw = struct.unpack_from(">I", data_bytes, 0)[0]
                    dose_rate = round(val_raw * 0.01, 4)
                    if 0.0 <= dose_rate <= 1000.0:   # sanity
                        samples.append((time.time(), dose_rate))
            consumed = end
            i = end
        if consumed:
            self._buf = self._buf[consumed:]
        return samples

    def _parse_ascii(self):
        # Decode what we can as ASCII, leave remainder in byte buf
        try:
            text = self._buf.decode("ascii", errors="replace")
            self._buf.clear()
        except Exception:
            return []

        self._ascii_buf += text
        samples = []

        while True:
            # Look for DR: token
            start = self._ascii_buf.find("DR:")
            if start == -1:
                # No token — keep last 64 chars in case it's a partial token
                self._ascii_buf = self._ascii_buf[-64:]
                break
            # Find unit marker after the value
            end = self._ascii_buf.find("uSv/h", start + 3)
            if end == -1:
                # Partial — keep from start
                self._ascii_buf = self._ascii_buf[start:]
                break
            segment = self._ascii_buf[start + 3:end]
            try:
                val = float(segment)
                if 0.0 <= val <= 1000.0:
                    samples.append((time.time(), val))
            except ValueError:
                pass
            self._ascii_buf = self._ascii_buf[end + 5:]

        return samples

# ---------------------------------------------------------------------------
# Anomaly engine (self-contained, no external deps)
# ---------------------------------------------------------------------------

def _median(values):
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return float(s[mid]) if n % 2 else 0.5 * (s[mid - 1] + s[mid])

def _mad(values, med):
    if not values:
        return 0.0
    return _median([abs(v - med) for v in values])

class AnomalyEngine:
    def __init__(self, out_dir, spike_threshold=SPIKE_THRESH,
                 spike_end=SPIKE_END, pre_seconds=30, post_seconds=60):
        self.spike_threshold = spike_threshold
        self.spike_end       = spike_end
        self.pre_seconds     = pre_seconds
        self.post_seconds    = post_seconds

        self._live   = deque(maxlen=DISPLAY_WINDOW)
        self._bg     = deque(maxlen=900)
        self._pre    = deque(maxlen=pre_seconds)

        self._spike    = None
        self._plateau  = None
        self._lock     = threading.Lock()
        self.spike_events   = []
        self.plateau_events = []

        ts = STAMP
        self.live_csv   = os.path.join(out_dir, f"live_{ts}.csv")
        self.spike_txt  = os.path.join(out_dir, f"spikes_{ts}.txt")
        self.spike_csv  = os.path.join(out_dir, f"spikes_{ts}.csv")
        self.plateau_csv = os.path.join(out_dir, f"plateaus_{ts}.csv")
        self._next_spike   = 1
        self._next_plateau = 1

        with open(self.live_csv, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp_iso", "unix", "dose_rate_uSvh"])
        with open(self.spike_csv, "w", newline="") as f:
            csv.writer(f).writerow(["event_id", "phase", "timestamp_iso",
                                    "unix", "dose_rate_uSvh"])
        with open(self.plateau_csv, "w", newline="") as f:
            csv.writer(f).writerow(["event_id", "start_iso", "end_iso",
                                    "duration_s", "mean_uSvh", "bg_uSvh", "ratio"])
        with open(self.spike_txt, "w") as f:
            f.write(f"# FS-5000 spike log {ts}\n\n")

    def add(self, ts_unix: float, rate: float):
        ts_iso = datetime.datetime.fromtimestamp(ts_unix).isoformat()
        self._live.append((ts_unix, rate))
        self._bg.append(rate)
        self._pre.append((ts_unix, rate))

        with open(self.live_csv, "a", newline="") as f:
            csv.writer(f).writerow([ts_iso, f"{ts_unix:.3f}", f"{rate:.4f}"])

        bg    = _median(self._bg) if len(self._bg) >= 30 else rate
        R     = rate / bg if bg > 0 else 1.0
        self._check_spike(ts_unix, ts_iso, rate, bg, R)
        self._check_plateau(ts_unix, ts_iso, rate, bg, R)

        return bg, R

    def get_display_data(self):
        """Return (times, rates) lists for gnuplot/ASCII rendering."""
        with self._lock:
            data = list(self._live)
        if not data:
            return [], []
        times = [d[0] for d in data]
        rates = [d[1] for d in data]
        return times, rates

    def current_bg(self):
        return _median(self._bg) if len(self._bg) >= 30 else None

    # ---- spike tracking ----

    def _check_spike(self, ts_unix, ts_iso, rate, bg, R):
        if self._spike is None:
            if rate >= self.spike_threshold:
                self._spike = {
                    "id": self._next_spike,
                    "start": ts_unix,
                    "end": ts_unix,
                    "bg": bg,
                    "samples": [],
                    "phase": "spike",
                }
                self._next_spike += 1
                for t0, d0 in self._pre:
                    self._spike["samples"].append(("pre", t0, d0))
                self._spike["samples"].append(("spike", ts_unix, rate))
        else:
            self._spike["samples"].append(("spike", ts_unix, rate))
            self._spike["end"] = ts_unix
            if rate <= self.spike_end:
                self._spike["phase"] = "post"
                self._spike["post_until"] = ts_unix + self.post_seconds
            if self._spike.get("phase") == "post" and \
               ts_unix >= self._spike.get("post_until", ts_unix + 1):
                self._finalize_spike()

    def _finalize_spike(self):
        ev = self._spike
        self._spike = None
        with self._lock:
            self.spike_events.append(ev)
        with open(self.spike_csv, "a", newline="") as f:
            w = csv.writer(f)
            for phase, ts, d in ev["samples"]:
                w.writerow([ev["id"], phase,
                             datetime.datetime.fromtimestamp(ts).isoformat(),
                             f"{ts:.3f}", f"{d:.4f}"])
        with open(self.spike_txt, "a") as f:
            f.write(f"Spike #{ev['id']}\n")
            f.write(f"  BG ~ {ev['bg']:.4f} µSv/h\n")
            t0 = ev["start"]
            for phase, ts, d in ev["samples"]:
                bar = "#" * max(1, int(d * 20))
                f.write(f"  {ts-t0:6.1f}s  {phase:5s}  {d:7.4f}  {bar}\n")
            f.write("\n")

    def _check_plateau(self, ts_unix, ts_iso, rate, bg, R):
        if len(self._live) < 30:
            return
        window = list(self._live)[-30:]
        vals = [d[1] for d in window]
        span = max(vals) - min(vals)
        duration = window[-1][0] - window[0][0]

        if self._plateau is None:
            if R >= 3.0 and span <= 0.03 and duration >= 30.0:
                self._plateau = {
                    "id": self._next_plateau,
                    "start": window[0][0],
                    "end": ts_unix,
                    "vals": vals[:],
                    "bg": bg,
                }
                self._next_plateau += 1
        else:
            self._plateau["end"] = ts_unix
            self._plateau["vals"].append(rate)
            if R < 2.0:
                self._finalize_plateau()

    def _finalize_plateau(self):
        ev = self._plateau
        self._plateau = None
        start, end = ev["start"], ev["end"]
        duration = end - start
        mean_val = sum(ev["vals"]) / len(ev["vals"])
        ratio = mean_val / ev["bg"] if ev["bg"] > 0 else 1.0
        with self._lock:
            self.plateau_events.append({
                "id": ev["id"], "start": start, "end": end,
                "duration": duration, "mean": mean_val,
                "bg": ev["bg"], "ratio": ratio,
            })
        with open(self.plateau_csv, "a", newline="") as f:
            csv.writer(f).writerow([
                ev["id"],
                datetime.datetime.fromtimestamp(start).isoformat(),
                datetime.datetime.fromtimestamp(end).isoformat(),
                f"{duration:.1f}", f"{mean_val:.4f}",
                f"{ev['bg']:.4f}", f"{ratio:.3f}",
            ])

# ---------------------------------------------------------------------------
# Gnuplot renderer
# ---------------------------------------------------------------------------

class GnuplotRenderer:
    """
    Drives a persistent gnuplot process with an X11 window.
    Data is written to a temp file; gnuplot re-reads on each refresh.
    """

    def __init__(self, data_file: str, title: str = "FS-5000 Live"):
        self._data_file = data_file
        self._title     = title
        self._proc      = None
        self._lock      = threading.Lock()

    def start(self):
        display = os.environ.get("DISPLAY", "")
        if not display:
            print("[gnuplot] DISPLAY not set — X11 rendering disabled.")
            print("          Set DISPLAY=:0 (local) or use ssh -X.")
            return False
        try:
            self._proc = subprocess.Popen(
                ["gnuplot", "-persistent"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Initial setup
            self._send(f"""
set terminal x11 title "{self._title}" size 900,450 persist
set style data linespoints
set pointsize 0.4
set grid
set xlabel "Time (s ago)"
set ylabel "Dose Rate (µSv/h)"
set yrange [0:*]
set key top right
set title "{self._title}"
set arrow 1 from graph 0,first {BG_HIGH} to graph 1,first {BG_HIGH} \
    nohead lc rgb "#f0883e" lw 1 dt 2
set arrow 2 from graph 0,first {BG_LOW} to graph 1,first {BG_LOW} \
    nohead lc rgb "#3fb950" lw 1 dt 2
set label 1 "BG high" at graph 0.01, first {BG_HIGH*1.05} tc rgb "#f0883e" font ",9"
set label 2 "BG low"  at graph 0.01, first {BG_LOW*1.05}  tc rgb "#3fb950" font ",9"
""")
            print(f"[gnuplot] X11 window opened (DISPLAY={display})")
            return True
        except FileNotFoundError:
            print("[gnuplot] Not found. Install: dnf install gnuplot")
            print("          Continuing with ASCII fallback only.")
            self._proc = None
            return False
        except Exception as e:
            print(f"[gnuplot] Failed to start: {e}")
            self._proc = None
            return False

    def update(self, times, rates, bg=None, spike_count=0, plateau_count=0):
        if self._proc is None or self._proc.poll() is not None:
            return
        if not times:
            return

        # Write data to temp file (relative time: seconds ago)
        now = times[-1]
        with open(self._data_file, "w") as f:
            for t, r in zip(times, rates):
                f.write(f"{t - now:.1f} {r:.4f}\n")

        extra_title = f"BG≈{bg:.3f} µSv/h" if bg else ""
        spike_info  = f"  Spikes:{spike_count}" if spike_count else ""
        plateau_info = f"  Plateaus:{plateau_count}" if plateau_count else ""

        cmd = (
            f'set title "{self._title}  {extra_title}{spike_info}{plateau_info}"\n'
            f'plot "{self._data_file}" using 1:2 with linespoints '
            f'lc rgb "#58a6ff" lw 1.5 pt 7 ps 0.3 title "µSv/h"\n'
        )
        self._send(cmd)

    def _send(self, cmd: str):
        if self._proc and self._proc.poll() is None:
            try:
                with self._lock:
                    self._proc.stdin.write(cmd.encode())
                    self._proc.stdin.flush()
            except BrokenPipeError:
                self._proc = None

    def close(self):
        if self._proc and self._proc.poll() is None:
            self._send("exit\n")
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.terminate()

# ---------------------------------------------------------------------------
# ASCII sparkline renderer (VT100, no deps)
# ---------------------------------------------------------------------------

SPARK_CHARS = " ▁▂▃▄▅▆▇█"

def _spark(values, width=60):
    if not values:
        return " " * width
    vmin = min(values)
    vmax = max(values)
    span = vmax - vmin if vmax != vmin else 1.0
    result = []
    step = max(1, len(values) // width)
    downsampled = values[-width * step::step][-width:]
    for v in downsampled:
        idx = int((v - vmin) / span * (len(SPARK_CHARS) - 1))
        result.append(SPARK_CHARS[idx])
    # Pad left
    result = [" "] * (width - len(result)) + result
    return "".join(result)

ANSI_RESET  = "\033[0m"
ANSI_GREEN  = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED    = "\033[31m"
ANSI_CYAN   = "\033[36m"
ANSI_BOLD   = "\033[1m"
ANSI_CLEAR  = "\033[H\033[J"   # home + clear screen

def _rate_color(rate):
    if rate > SPIKE_THRESH:
        return ANSI_RED + ANSI_BOLD
    if rate > BG_HIGH:
        return ANSI_YELLOW
    return ANSI_GREEN

def render_ascii(times, rates, bg, engine, sample_count):
    """Render a full-screen ASCII display to stdout."""
    sys.stdout.write(ANSI_CLEAR)

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current = rates[-1] if rates else 0.0
    color   = _rate_color(current)

    # Header
    print(f"{ANSI_CYAN}{ANSI_BOLD}╔══════════════════════════════════════════════"
          f"═══════════════════╗{ANSI_RESET}")
    print(f"{ANSI_CYAN}{ANSI_BOLD}║  FS-5000 LIVE MONITOR  {ANSI_RESET}"
          f"  {now_str}  "
          f"  samples: {sample_count:>6d}  "
          f"{ANSI_CYAN}{ANSI_BOLD}║{ANSI_RESET}")
    print(f"{ANSI_CYAN}{ANSI_BOLD}╚══════════════════════════════════════════════"
          f"═══════════════════╝{ANSI_RESET}")

    # Current reading
    print()
    print(f"  Current:  {color}{current:8.4f} µSv/h{ANSI_RESET}", end="")
    if bg:
        ratio = current / bg if bg > 0 else 1.0
        r_color = _rate_color(current)
        print(f"    BG≈{bg:.4f}   ratio: {r_color}{ratio:.2f}×{ANSI_RESET}", end="")
    print()

    # Sparkline
    if rates:
        spark = _spark(rates, width=68)
        # Color band markers
        vmin = min(rates)
        vmax = max(rates)
        print(f"\n  {ANSI_CYAN}Last {len(rates)} samples ({DISPLAY_WINDOW}s window):{ANSI_RESET}")
        print(f"  {ANSI_GREEN}↑{vmax:.3f}{ANSI_RESET}  {spark}  "
              f"{ANSI_GREEN}↓{vmin:.3f}{ANSI_RESET}")
        print(f"  {' ' * 8}{'└' + '─' * 68 + '┘'}")
        print(f"  {'older':>38}{'newer':>32}")

    # Thresholds
    print()
    bg_status = ""
    if current > SPIKE_THRESH:
        bg_status = f"{ANSI_RED}{ANSI_BOLD}  !! SPIKE THRESHOLD EXCEEDED !!{ANSI_RESET}"
    elif current > BG_HIGH:
        bg_status = f"{ANSI_YELLOW}  ^ ABOVE BACKGROUND HIGH{ANSI_RESET}"
    elif current < BG_LOW:
        bg_status = f"{ANSI_CYAN}  (below background low){ANSI_RESET}"
    else:
        bg_status = f"{ANSI_GREEN}  (within background band){ANSI_RESET}"
    print(f"  Thresholds: BG_low={BG_LOW}  BG_high={BG_HIGH}  "
          f"spike={SPIKE_THRESH} µSv/h{bg_status}")

    # Event counts
    with engine._lock:
        n_spikes   = len(engine.spike_events)
        n_plateaus = len(engine.plateau_events)
    in_spike   = "  [SPIKE ACTIVE]"   if engine._spike   else ""
    in_plateau = "  [PLATEAU ACTIVE]" if engine._plateau else ""
    print(f"\n  Events:  spikes={n_spikes}{in_spike}   "
          f"plateaus={n_plateaus}{in_plateau}")

    # Last spike summary
    with engine._lock:
        last_spike = engine.spike_events[-1] if engine.spike_events else None
    if last_spike:
        peak = max(d for _, _, d in last_spike["samples"])
        dur  = last_spike["end"] - last_spike["start"]
        t_str = datetime.datetime.fromtimestamp(last_spike["start"]).strftime(
            "%H:%M:%S")
        print(f"  Last spike #{last_spike['id']}: "
              f"peak={peak:.4f} µSv/h  dur={dur:.0f}s  at {t_str}")

    print(f"\n  {ANSI_CYAN}Ctrl-C to stop and finalize logs{ANSI_RESET}")
    sys.stdout.flush()

# ---------------------------------------------------------------------------
# Serial reader thread
# ---------------------------------------------------------------------------

class SerialReader(threading.Thread):
    """
    Reads from FS-5000, feeds LiveParser, pushes samples to AnomalyEngine.
    Stores last N samples in a thread-safe deque for the display thread.
    """

    def __init__(self, port_name: str, engine: AnomalyEngine,
                 sample_queue: deque, stop_event: threading.Event):
        super().__init__(daemon=True, name="serial-reader")
        self.port_name    = port_name
        self.engine       = engine
        self.sample_queue = sample_queue  # (ts, rate) pairs
        self.stop_event   = stop_event
        self.total_samples = 0
        self.parse_errors  = 0
        self._parser       = LiveParser()

    def run(self):
        try:
            with serial.Serial(self.port_name, BAUD, timeout=0.1) as port:
                print(f"[serial] Opened {self.port_name} @ {BAUD}")
                # Stop any lingering stream
                port.write(LIVE_STOP)
                time.sleep(0.3)
                port.reset_input_buffer()
                # Start live stream
                port.write(LIVE_START)
                print(f"[serial] live_start sent: {LIVE_START.hex()}")
                time.sleep(0.5)

                # Check ACK
                ack_raw = bytearray()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    n = port.in_waiting
                    if n:
                        ack_raw.extend(port.read(n))
                    time.sleep(0.05)
                if ack_raw:
                    print(f"[serial] ACK: {ack_raw[:32].hex()}")
                    ascii_ack = "".join(
                        chr(b) if 32 <= b < 127 else "." for b in ack_raw[:32])
                    print(f"[serial] ACK ASCII: {ascii_ack}")
                else:
                    print("[serial] WARNING: No ACK received from live_start.")
                    print("         Continuing anyway — some firmware versions")
                    print("         start streaming without ACK.")

                # Main read loop
                while not self.stop_event.is_set():
                    n = port.in_waiting
                    if n:
                        raw = port.read(n)
                        samples = self._parser.feed(raw)
                        for ts, rate in samples:
                            self.engine.add(ts, rate)
                            self.sample_queue.append((ts, rate))
                            self.total_samples += 1
                    else:
                        time.sleep(0.02)

                # Clean stop
                port.write(LIVE_STOP)
                time.sleep(0.3)
                print(f"[serial] Stopped. Total samples: {self.total_samples}")

        except serial.SerialException as e:
            print(f"[serial] ERROR: {e}")
            self.stop_event.set()

# ---------------------------------------------------------------------------
# Display thread
# ---------------------------------------------------------------------------

class DisplayThread(threading.Thread):
    def __init__(self, engine: AnomalyEngine, gnuplot: GnuplotRenderer,
                 stop_event: threading.Event, ascii_only: bool,
                 sample_queue: deque):
        super().__init__(daemon=True, name="display")
        self.engine       = engine
        self.gnuplot      = gnuplot
        self.stop_event   = stop_event
        self.ascii_only   = ascii_only
        self.sample_queue = sample_queue
        self._last_gnuplot = 0.0
        self._total        = 0

    def run(self):
        while not self.stop_event.is_set():
            self._total = len(self.sample_queue)
            times, rates = self.engine.get_display_data()
            bg = self.engine.current_bg()

            # ASCII display — update every second
            render_ascii(times, rates, bg, self.engine, self._total)

            # Gnuplot — update every GNUPLOT_INTERVAL seconds
            now = time.time()
            if not self.ascii_only and (now - self._last_gnuplot) >= GNUPLOT_INTERVAL:
                with self.engine._lock:
                    n_spikes   = len(self.engine.spike_events)
                    n_plateaus = len(self.engine.plateau_events)
                self.gnuplot.update(times, rates, bg, n_spikes, n_plateaus)
                self._last_gnuplot = now

            time.sleep(1.0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="FS-5000 headless live monitor")
    ap.add_argument("--port",        help="Serial port, e.g. /dev/ttyUSB0")
    ap.add_argument("--out",         default=".", help="Output directory")
    ap.add_argument("--no-gnuplot",  action="store_true",
                    help="Disable gnuplot X11 window (ASCII only)")
    ap.add_argument("--spike-threshold", type=float, default=SPIKE_THRESH)
    ap.add_argument("--spike-end",       type=float, default=SPIKE_END)
    ap.add_argument("--pre",             type=int,   default=30)
    ap.add_argument("--post",            type=int,   default=60)
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    port_name = args.port or find_port()
    data_file = os.path.join(out_dir, f"gnuplot_live_{STAMP}.dat")

    engine = AnomalyEngine(
        out_dir,
        spike_threshold=args.spike_threshold,
        spike_end=args.spike_end,
        pre_seconds=args.pre,
        post_seconds=args.post,
    )

    gnuplot = GnuplotRenderer(data_file, title=f"FS-5000 Live  [{port_name}]")
    gp_ok   = False if args.no_gnuplot else gnuplot.start()

    stop_event    = threading.Event()
    sample_queue  = deque(maxlen=100000)

    reader  = SerialReader(port_name, engine, sample_queue, stop_event)
    display = DisplayThread(engine, gnuplot, stop_event,
                            ascii_only=(not gp_ok), sample_queue=sample_queue)

    def _sigint(sig, frame):
        print("\n[main] Interrupt received — stopping...")
        stop_event.set()

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    reader.start()
    display.start()

    print(f"[main] Live monitor running.  Output: {out_dir}")
    print(f"[main] Ctrl-C to stop.")

    reader.join()
    display.join(timeout=2.0)
    gnuplot.close()

    # Final summary
    print(f"\n{'='*60}")
    print(f"Session complete.")
    print(f"  Total samples : {reader.total_samples}")
    with engine._lock:
        print(f"  Spike events  : {len(engine.spike_events)}")
        print(f"  Plateau events: {len(engine.plateau_events)}")
    print(f"  Live CSV      : {engine.live_csv}")
    print(f"  Spike CSV     : {engine.spike_csv}")
    print(f"  Spike log     : {engine.spike_txt}")
    print(f"  Plateau CSV   : {engine.plateau_csv}")
    print("="*60)


if __name__ == "__main__":
    main()

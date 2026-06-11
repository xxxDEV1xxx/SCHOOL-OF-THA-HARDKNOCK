#!/usr/bin/env python3
"""
================================================================================
  SERIAL DOCUMENTING ARCHITECTURE RESEARCH (SDARâ„¢)
  VM Guard â€” Kali Purple Side (Passive Watcher)
  Kernel  : 6.16.8+kali-amd64
  Device  : /dev/ttyS0 (VMware named pipe â†’ ttyS0)
  Inventor: Christopher T. Williams
  Date    : 20 March 2026 (PST) / 21 March 2026 (UTC)

  AI ASSISTANCE DISCLOSURE (Appendix A):
    Grok (xAI) and Claude (Anthropic) assisted solely in translating the
    inventor's architecture into executable code. All design decisions,
    forensic methodology, topology, and evidence strategy are the original,
    sole work of Christopher T. Williams.

  ROLE: PASSIVE WATCHER â€” READ-ONLY OUTPUT.
    This process NEVER writes to ttyS0 unsolicited.
    All keystroke input to the VM originates exclusively from the
    Windows host guard (single input authority enforced by architecture).
    
    VM-side only:
      - Logs all host-injected commands received on ttyS0
      - Emits periodic heartbeat (can be disabled)
      - Processes host override commands
      - Never initiates writes unprompted
================================================================================
"""

import os
import sys
import time
import signal
import hashlib
import logging
import termios
import tty
import select
import datetime
import subprocess
from pathlib import Path

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# CONFIGURATION
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
SERIAL_DEV      = "/dev/ttyS0"
LOG_DIR         = "/var/log/sdar"
HEARTBEAT_SEC   = 30       # 0 to disable heartbeat
BAUD            = 115200

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# LOGGING â€” hash-chained, tamper-evident
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
ts_str      = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
LOG_FILE    = f"{LOG_DIR}/sdar-vm-{ts_str}.log"
prev_hash   = "0" * 64

def chain_log(level: str, msg: str) -> None:
    global prev_hash
    ts      = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    content = f"{ts}|{level}|{msg}"
    h_input = (prev_hash + content).encode()
    cur_hash = hashlib.sha256(h_input).hexdigest()
    prev_hash = cur_hash
    line = f"{ts} | {level} | CHAIN:{cur_hash} | {msg}"
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SERIAL PORT SETUP
# Opens ttyS0 raw, 115200 8N1, no flow control
# Does NOT disturb LUKS/initramfs â€” only active post-boot
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def open_serial(dev: str, baud: int):
    fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    # cfmakeraw equivalent
    attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK |
                  termios.ISTRIP | termios.INLCR  | termios.IGNCR  |
                  termios.ICRNL  | termios.IXON)
    attrs[1] &= ~termios.OPOST
    attrs[2] &= ~(termios.CSIZE | termios.PARENB)
    attrs[2] |=  (termios.CS8 | termios.CREAD | termios.CLOCAL)
    attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON |
                  termios.ISIG | termios.IEXTEN)
    attrs[4] = termios.B115200
    attrs[5] = termios.B115200
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    chain_log("INIT", f"Serial {dev} opened: {baud}/8N1/NoFlow")
    return fd

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# COMMAND PROCESSOR â€” handles host-injected commands
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def process_host_command(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8", errors="replace").strip()
    except Exception:
        text = repr(raw)

    chain_log("HOST-CMD", f"Received [{len(raw)}B]: {text}")

    # VM-side response to specific host commands (output only, not input)
    if text.upper() == "SDAR:STATUS":
        status = subprocess.check_output(
            ["bash","-c","uptime && free -h && df -h / && uname -a"],
            stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        chain_log("STATUS", status.replace("\n"," | "))

    elif text.upper() == "SDAR:PROCS":
        ps = subprocess.check_output(
            ["ps","aux","--sort=-%cpu"],
            stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        chain_log("PROCS", ps[:1000])

    elif text.upper() == "SDAR:NETSTAT":
        ns = subprocess.check_output(
            ["ss","-tulnp"],
            stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        chain_log("NETSTAT", ns[:1000])

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# HEARTBEAT â€” periodic VM state to serial (output only)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def emit_heartbeat(fd: int) -> None:
    if HEARTBEAT_SEC == 0:
        return
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    up = open("/proc/uptime").read().split()[0]
    hb = f"[SDAR-VM-HEARTBEAT] {ts} uptime={up}s\r\n"
    # Write heartbeat out to host (VM â†’ Host direction, this is output not input)
    try:
        os.write(fd, hb.encode())
    except Exception as e:
        chain_log("ERROR", f"Heartbeat write failed: {e}")

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# MAIN GUARD LOOP
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def main():
    chain_log("INIT", "â•â•â• SDAR VM GUARD STARTING â•â•â•")
    chain_log("INIT", f"Inventor: Christopher T. Williams")
    chain_log("INIT", f"Kernel  : {os.uname().release}")
    chain_log("INIT", f"Device  : {SERIAL_DEV}")
    chain_log("INIT", "Role    : PASSIVE WATCHER â€” host has sole input authority")

    fd = open_serial(SERIAL_DEV, BAUD)

    running        = True
    last_heartbeat = time.monotonic()

    def _sig(signum, frame):
        nonlocal running
        chain_log("INIT", f"Signal {signum} received â€” shutting down")
        running = False

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    buf = b""
    chain_log("INIT", "Guard loop active. Listening for host commands...")

    while running:
        try:
            # Non-blocking read from ttyS0
            r, _, _ = select.select([fd], [], [], 1.0)
            if r:
                chunk = os.read(fd, 256)
                if chunk:
                    buf += chunk
                    # Process complete lines
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        process_host_command(line)

            # Heartbeat
            if HEARTBEAT_SEC > 0:
                if time.monotonic() - last_heartbeat >= HEARTBEAT_SEC:
                    emit_heartbeat(fd)
                    last_heartbeat = time.monotonic()

        except Exception as e:
            chain_log("ERROR", f"Guard loop: {e}")
            time.sleep(1)

    os.close(fd)
    chain_log("INIT", f"â•â•â• SDAR VM GUARD STOPPED | Chain tail: {prev_hash} â•â•â•")

if __name__ == "__main__":
    main()

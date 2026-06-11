#!/usr/bin/env python3
"""
fs5000_dd.py  —  Raw device read, no protocol, no framing, no stopping.
Equivalent to:  dd if=/dev/ttyUSB0 of=fs5000_raw.bin

Opens the serial port and reads every byte the device sends
until you press Ctrl+C. Writes raw bytes directly to disk as they arrive.
No parsing. No interpretation. No timeouts cutting you off.

Usage:
    python fs5000_dd.py
    python fs5000_dd.py --port COM3
    python fs5000_dd.py --port COM3 --out fs5000_raw.bin

The .hex.txt and .csv are generated from the .bin after you stop.
"""

import argparse
import datetime
import os
import sys
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("pip install pyserial")
    sys.exit(1)

CH340_VID = 0x1A86
CH340_PID = 0x7523
BAUD      = 115200

def find_port(forced=None):
    if forced:
        return forced
    for p in serial.tools.list_ports.comports():
        if p.vid == CH340_VID and p.pid == CH340_PID:
            print(f"Found: {p.device}  [{p.description}]")
            return p.device
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("No ports found. Install CH340 driver.")
        sys.exit(1)
    print("Ports available:")
    for p in ports:
        print(f"  {p.device}  {p.description}")
    print("Use --port COMx")
    sys.exit(1)

def write_hex(data, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'{len(data)} bytes\n')
        f.write(f'OFFSET    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII\n')
        f.write('-'*74 + '\n')
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            l = ' '.join(f'{b:02X}' for b in chunk[:8])
            r = ' '.join(f'{b:02X}' for b in chunk[8:])
            a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            f.write(f'{i:06X}    {l:<23}  {r:<23}  {a}\n')

def write_csv(data, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('offset_dec,offset_hex,byte_dec,byte_hex,ascii\n')
        for i, b in enumerate(data):
            a = chr(b) if 32 <= b < 127 else ''
            f.write(f'{i},{i:06X},{b},{b:02X},{a}\n')

def main():
    ap = argparse.ArgumentParser(description='Raw FS-5000 device dump — dd equivalent')
    ap.add_argument('--port', help='e.g. COM3')
    ap.add_argument('--out',  default='fs5000_raw.bin', help='output .bin filename')
    ap.add_argument('--send', default='', help='hex bytes to send before reading, e.g. "aa0403b155"')
    args = ap.parse_args()

    port_name = find_port(args.port)
    out_bin   = args.out
    out_hex   = out_bin.replace('.bin', '.hex.txt')
    out_csv   = out_bin.replace('.bin', '.csv')

    print(f"Port:   {port_name} @ {BAUD} baud")
    print(f"Output: {out_bin}")
    print(f"Ctrl+C to stop and write files.")
    print()

    buf = bytearray()

    with serial.Serial(port_name, BAUD, timeout=0) as port:
        # Optional: send a command first
        if args.send:
            tx = bytes.fromhex(args.send.replace(' ',''))
            port.write(tx)
            print(f"Sent: {tx.hex().upper()}")

        try:
            while True:
                chunk = port.read(4096)
                if chunk:
                    buf.extend(chunk)
                    sys.stdout.write(f'\r{len(buf)} bytes received...')
                    sys.stdout.flush()
                else:
                    time.sleep(0.005)

        except KeyboardInterrupt:
            pass

    print(f"\n\nTotal received: {len(buf)} bytes")

    if not buf:
        print("Nothing received.")
        return

    # Write all three formats
    with open(out_bin, 'wb') as f:
        f.write(bytes(buf))
    print(f"BIN → {out_bin}  ({len(buf)} bytes)")

    write_hex(bytes(buf), out_hex)
    print(f"HEX → {out_hex}")

    write_csv(bytes(buf), out_csv)
    print(f"CSV → {out_csv}")

if __name__ == '__main__':
    main()

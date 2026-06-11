#!/usr/bin/env python3
"""
comdump.py  —  Universal serial port raw dump
dd if=/dev/ttyX of=raw.bin  for any COM port on any OS

Reads every byte from the port. Writes to disk. No protocol.
No framing. No parsing. No timeouts. Runs until Ctrl+C.

Works with: FS-5000, LND counter, Arduino, anything serial.

Usage:
    python comdump.py --port COM3
    python comdump.py --port COM3 --baud 9600
    python comdump.py --port COM3 --out mydevice.bin
    python comdump.py --port COM3 --baud 115200 --out fs5000.bin
    python comdump.py --list

On Linux/Mac:
    python comdump.py --port /dev/ttyUSB0
    python comdump.py --port /dev/tty.usbserial-1440
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
    print("ERROR: pyserial not installed.")
    print("Run: pip install pyserial")
    sys.exit(1)


def list_ports():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("No serial ports detected.")
        return
    print(f"{'PORT':<16} {'VID:PID':<12} {'DESCRIPTION'}")
    print('-' * 70)
    for p in sorted(ports, key=lambda x: x.device):
        vidpid = f"{p.vid:04X}:{p.pid:04X}" if p.vid else "----:----"
        print(f"{p.device:<16} {vidpid:<12} {p.description}")


def write_hex(data: bytes, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'{os.path.basename(path)}\n')
        f.write(f'{len(data)} bytes  |  '
                f'dumped {datetime.datetime.now().isoformat()}\n')
        f.write(f'OFFSET    '
                f'00 01 02 03 04 05 06 07  '
                f'08 09 0A 0B 0C 0D 0E 0F  ASCII\n')
        f.write('-' * 74 + '\n')
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            l = ' '.join(f'{b:02X}' for b in chunk[:8])
            r = ' '.join(f'{b:02X}' for b in chunk[8:])
            a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            f.write(f'{i:06X}    {l:<23}  {r:<23}  {a}\n')


def write_csv(data: bytes, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('offset_dec,offset_hex,byte_dec,byte_hex,ascii\n')
        for i, b in enumerate(data):
            a = chr(b) if 32 <= b < 127 else ''
            f.write(f'{i},{i:06X},{b},{b:02X},{a}\n')


def main():
    ap = argparse.ArgumentParser(
        description='Universal serial port raw dump — dd equivalent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--port',  help='Serial port, e.g. COM3 or /dev/ttyUSB0')
    ap.add_argument('--baud',  type=int, default=115200,
                    help='Baud rate (default 115200)')
    ap.add_argument('--out',   default='',
                    help='Output base name (default: COMx_TIMESTAMP)')
    ap.add_argument('--list',  action='store_true',
                    help='List available serial ports and exit')
    ap.add_argument('--no-hex', action='store_true',
                    help='Skip .hex.txt output')
    ap.add_argument('--no-csv', action='store_true',
                    help='Skip .csv output')
    args = ap.parse_args()

    if args.list:
        list_ports()
        return

    if not args.port:
        print("ERROR: --port required. Use --list to see available ports.")
        list_ports()
        sys.exit(1)

    port_name = args.port
    baud      = args.baud
    stamp     = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_port = port_name.replace('/', '_').replace('\\', '_').replace(':', '')
    base      = args.out if args.out else f'{safe_port}_{stamp}'
    base      = base.replace('.bin', '')

    out_bin = base + '.bin'
    out_hex = base + '.hex.txt'
    out_csv = base + '.csv'

    print()
    print(f"  Port  : {port_name}")
    print(f"  Baud  : {baud}")
    print(f"  Output: {out_bin}")
    print()
    print("  Reading... Ctrl+C to stop and write files.")
    print()

    buf       = bytearray()
    last_print = time.monotonic()

    try:
        with serial.Serial(
            port     = port_name,
            baudrate = baud,
            bytesize = serial.EIGHTBITS,
            parity   = serial.PARITY_NONE,
            stopbits = serial.STOPBITS_ONE,
            xonxoff  = False,
            rtscts   = False,
            dsrdtr   = False,
            timeout  = 0,          # non-blocking read
        ) as port:

            while True:
                waiting = port.in_waiting
                if waiting:
                    chunk = port.read(waiting)
                    buf.extend(chunk)

                now = time.monotonic()
                if now - last_print >= 0.25:
                    rate_bps = len(buf) / max(now - (last_print - 0.25), 0.001)
                    sys.stdout.write(
                        f'\r  {len(buf):>10} bytes  '
                        f'({rate_bps:.0f} B/s)    '
                    )
                    sys.stdout.flush()
                    last_print = now

                if not waiting:
                    time.sleep(0.001)

    except KeyboardInterrupt:
        pass
    except serial.SerialException as e:
        print(f"\nSerial error: {e}")
        if buf:
            print("Writing what was received before error...")
        else:
            sys.exit(1)

    print(f"\n\n  Stopped. {len(buf)} bytes captured.")

    if not buf:
        print("  Nothing received.")
        return

    # Write BIN
    with open(out_bin, 'wb') as f:
        f.write(bytes(buf))
    print(f"  BIN → {out_bin}  ({len(buf)} bytes)")

    # Write HEX
    if not args.no_hex:
        write_hex(bytes(buf), out_hex)
        print(f"  HEX → {out_hex}")

    # Write CSV
    if not args.no_csv:
        write_csv(bytes(buf), out_csv)
        print(f"  CSV → {out_csv}")

    print()


if __name__ == '__main__':
    main()

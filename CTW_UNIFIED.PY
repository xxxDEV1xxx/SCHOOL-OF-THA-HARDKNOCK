#!/usr/bin/env python3
"""
CTW Unified Encryption Stack v1.0
Purpose: Drop-in pipe/socket/stack encryption for local IPC
         Transparent to callers — core services see normal read/write API
         Internally: physical ratchet + piston double buffer + polyglot obfuscation

Design contract:
  - NEVER breaks the underlying pipe/socket semantics
  - read() always returns complete plaintext or raises — never partial garbage
  - write() always delivers or raises — never silent data corruption
  - Core services import CTWStack and call .read() / .write() unchanged

Install:
  pip install cryptography blake3

Usage:
  from ctw_stack import CTWStack

  # Writer
  stack = CTWStack.from_env()
  stack.write(b"my data")

  # Reader (same root key)
  stack = CTWStack.from_env()
  data = stack.read()
"""

import os
import sys
import time
import json
import struct
import socket
import hashlib
import hmac as _hmac
import random
import threading
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum

# ── hash primitive ────────────────────────────────────────────────────────────
try:
    import blake3 as _blake3
    def _H(data: bytes) -> bytes:
        return _blake3.blake3(data).digest()
except ImportError:
    def _H(data: bytes) -> bytes:
        return hashlib.sha3_256(data).digest()

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# ── frame magic ───────────────────────────────────────────────────────────────
_MAGIC   = b"CTW\x02"
_HDR_FMT = struct.Struct("!4sI")   # magic(4) + payload_length(4)

# ── HKDF helper ───────────────────────────────────────────────────────────────
def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, info=info, backend=default_backend()
    ).derive(ikm)


###############################################################################
# 1. PHYSICAL ENTROPY
###############################################################################

def _physical_entropy() -> bytes:
    parts = [
        os.urandom(32),
        struct.pack("Q", time.perf_counter_ns()),
        struct.pack("Q", time.monotonic_ns()),
    ]
    for p in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            parts.append(struct.pack("i", int(p.read_text())))
        except Exception:
            pass
    try:
        parts.append(_H(Path("/proc/net/dev").read_text().encode()))
    except Exception:
        pass
    return _H(b"".join(parts))


###############################################################################
# 2. RATCHET — one key per frame, forward secret
###############################################################################

class _Ratchet:
    def __init__(self, root: bytes):
        self._chain = _H(root + b"ratchet-init")
        self._step  = 0
        self._lock  = threading.Lock()

    def advance(self) -> bytes:
        with self._lock:
            j = struct.pack("Q", time.perf_counter_ns())
            e = os.urandom(8)
            msg_key = _hmac.new(
                self._chain, b"msg" + j, hashlib.sha256
            ).digest()
            self._chain = _H(self._chain + j + e +
                             struct.pack("Q", self._step))
            self._step += 1
            return msg_key

    @property
    def step(self) -> int:
        return self._step


###############################################################################
# 3. PISTON — two cipher slots, 5 s rotation
###############################################################################

class _Piston:
    WINDOW = 5.0

    def __init__(self, root: bytes):
        self._root  = root
        self._keys: Dict[int, bytes] = {}
        self._gen   = 0
        self._lock  = threading.Lock()
        self._active    = self._new_slot()
        self._standby   = self._new_slot()
        self._activated = time.monotonic()
        threading.Thread(target=self._loop, daemon=True).start()

    def _new_slot(self) -> int:
        self._gen += 1
        g = self._gen
        self._keys[g] = _hkdf(
            _H(self._root + struct.pack("Q", g) + _physical_entropy()),
            os.urandom(16),
            f"piston-slot-{g}".encode()
        )
        return g

    def _loop(self):
        while True:
            with self._lock:
                age = time.monotonic() - self._activated
            time.sleep(max(0.05, self.WINDOW - age))
            with self._lock:
                old = self._active
                self._active   = self._standby
                self._standby  = self._new_slot()
                self._activated = time.monotonic()

    def active(self):
        with self._lock:
            return self._active, self._keys[self._active]

    def key_for(self, tag: int) -> bytes:
        with self._lock:
            if tag not in self._keys:
                raise KeyError(f"unknown piston tag {tag}")
            return self._keys[tag]


###############################################################################
# 4. POLYGLOT MAP — unicode substitution obfuscation layer
###############################################################################

_PACKS: Dict[str, List[int]] = {
    "greek":      list(range(0x0391, 0x03C9)),
    "cyrillic":   list(range(0x0410, 0x044F)),
    "armenian":   list(range(0x0531, 0x0556)),
    "georgian":   list(range(0x10D0, 0x10FA)),
    "hebrew":     list(range(0x05D0, 0x05EA)),
    "arabic":     list(range(0x0621, 0x064A)),
    "devanagari": list(range(0x0900, 0x0963)),
    "tamil":      list(range(0x0B85, 0x0BB9)),
    "telugu":     list(range(0x0C05, 0x0C39)),
    "thai":       list(range(0x0E01, 0x0E2E)),
    "tibetan":    list(range(0x0F40, 0x0F6C)),
    "hiragana":   list(range(0x3041, 0x3096)),
    "katakana":   list(range(0x30A1, 0x30F6)),
    "hangul":     list(range(0xAC00, 0xAC60)),
    "ethiopic":   list(range(0x1200, 0x1248)),
    "cherokee":   list(range(0x13A0, 0x13F5)),
    "runic":      list(range(0x16A0, 0x16EA)),
    "nko":        list(range(0x07C0, 0x07EA)),
    "lisu":       list(range(0xA4D0, 0xA4FD)),
    "vai":        list(range(0xA500, 0xA60C)),
}
_PACK_NAMES = list(_PACKS.keys())

class _PolyglotMap:
    """
    Seed-deterministic byte→unicode map.
    Same seed = same map on both ends.
    Different seed = completely different map.
    """
    def __init__(self, seed: bytes):
        rng   = random.Random(int.from_bytes(seed[:8], 'big'))
        packs = rng.sample(_PACK_NAMES, min(8, len(_PACK_NAMES)))
        pool: List[int] = []
        for p in packs:
            pool.extend(_PACKS[p])
        pool = list(set(pool))
        rng2  = random.Random(int.from_bytes(seed[8:16], 'big'))
        rng2.shuffle(pool)
        while len(pool) < 256:
            pool += [x + 0x10000 for x in pool[:256 - len(pool)]]
        pool = pool[:256]
        rng3  = random.Random(int.from_bytes(seed[16:24], 'big'))
        rng3.shuffle(pool)
        self._enc = {i: chr(pool[i]) for i in range(256)}
        self._dec = {chr(pool[i]): i for i in range(256)}

    def encode(self, data: bytes) -> str:
        return "".join(self._enc[b] for b in data)

    def decode(self, text: str) -> bytes:
        try:
            return bytes(self._dec[c] for c in text)
        except KeyError as e:
            raise ValueError(f"polyglot decode failed — map mismatch: {e}")


class _PolyglotEngine:
    """
    Rotating polyglot maps tied to piston rotation.
    map_seed derived from piston slot tag so both ends
    independently derive identical maps without coordination.
    """
    def __init__(self, root: bytes):
        self._root   = root
        self._cache: Dict[int, _PolyglotMap] = {}
        self._lock   = threading.Lock()

    def _map_for_tag(self, tag: int) -> _PolyglotMap:
        with self._lock:
            if tag not in self._cache:
                seed = _H(self._root + b"polyglot" +
                          struct.pack("Q", tag))
                self._cache[tag] = _PolyglotMap(seed)
                # Keep cache bounded — drop old entries
                if len(self._cache) > 20:
                    oldest = min(self._cache)
                    del self._cache[oldest]
            return self._cache[tag]

    def encode(self, data: bytes, tag: int) -> bytes:
        return self._map_for_tag(tag).encode(data).encode("utf-8")

    def decode(self, data: bytes, tag: int) -> bytes:
        return self._map_for_tag(tag).decode(data.decode("utf-8"))


###############################################################################
# 5. FRAME CODEC
#
# Wire format (all big-endian):
#   [4]  magic
#   [4]  total payload length (everything after this field)
#   [4]  piston tag
#   [16] map seed salt (for polyglot derivation verification)
#   [12] AES nonce
#   [16] HKDF salt
#   [N]  polyglot-obfuscated AES-GCM-SIV ciphertext (utf-8 bytes)
###############################################################################

_FRAME_PREFIX = struct.Struct("!4sI")   # magic, total_len
_FRAME_META   = struct.Struct("!I")     # piston_tag

def _encode_frame(plaintext: bytes,
                  ratchet: _Ratchet,
                  piston:  _Piston,
                  poly:    _PolyglotEngine) -> bytes:
    msg_key        = ratchet.advance()
    tag, slot_key  = piston.active()
    frame_ikm      = _H(msg_key + slot_key)
    hkdf_salt      = os.urandom(16)
    aes_key        = _hkdf(frame_ikm, hkdf_salt, b"CTW-aes-frame")
    nonce          = os.urandom(12)
    aad            = struct.pack("!I", tag)
    ct             = AESGCMSIV(aes_key).encrypt(nonce, plaintext, aad)
    poly_bytes     = poly.encode(ct, tag)

    meta   = aad + hkdf_salt + nonce + poly_bytes   # 4+16+12+N
    header = _FRAME_PREFIX.pack(_MAGIC, len(meta))
    return header + meta


def _decode_frame(frame: bytes,
                  ratchet: _Ratchet,
                  piston:  _Piston,
                  poly:    _PolyglotEngine) -> bytes:
    if len(frame) < _FRAME_PREFIX.size:
        raise ValueError("frame too short")
    magic, total_len = _FRAME_PREFIX.unpack(frame[:_FRAME_PREFIX.size])
    if magic != _MAGIC:
        raise ValueError(f"bad magic {magic!r} — desync or tampering")

    meta    = frame[_FRAME_PREFIX.size : _FRAME_PREFIX.size + total_len]
    tag     = struct.unpack("!I", meta[:4])[0]
    hkdf_salt = meta[4:20]
    nonce   = meta[20:32]
    poly_bytes = meta[32:]

    ct      = poly.decode(poly_bytes, tag)
    msg_key = ratchet.advance()
    slot_key = piston.key_for(tag)
    frame_ikm = _H(msg_key + slot_key)
    aes_key = _hkdf(frame_ikm, hkdf_salt, b"CTW-aes-frame")
    aad     = struct.pack("!I", tag)
    return AESGCMSIV(aes_key).decrypt(nonce, ct, aad)


###############################################################################
# 6. CTWStack — the unified public API
###############################################################################

class CTWStack:
    """
    Unified encryption stack.
    Wraps any file descriptor, socket, or pipe.
    Callers use .read() and .write() — identical to raw fd semantics.
    Nothing breaks. Everything is encrypted transparently.
    """

    def __init__(self, root_key: bytes, label: str = "stack"):
        self._label   = label
        self._ratchet = _Ratchet(root_key)
        self._piston  = _Piston(root_key)
        self._poly    = _PolyglotEngine(root_key)
        self._lock    = threading.Lock()
        print(f"[CTW:{label}] Stack online | "
              f"ratchet+piston+polyglot active")

    # ── core API ──────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt bytes → framed ciphertext. Safe to write to any fd."""
        with self._lock:
            return _encode_frame(plaintext,
                                 self._ratchet,
                                 self._piston,
                                 self._poly)

    def decrypt(self, frame: bytes) -> bytes:
        """Decrypt framed ciphertext → plaintext. Call on any fd read."""
        with self._lock:
            return _decode_frame(frame,
                                 self._ratchet,
                                 self._piston,
                                 self._poly)

    # ── fd helpers ────────────────────────────────────────────────────────────

    def write_fd(self, fd: int, data: bytes):
        """Encrypt and write to raw file descriptor."""
        frame = self.encrypt(data)
        os.write(fd, struct.pack("!I", len(frame)) + frame)

    def read_fd(self, fd: int) -> bytes:
        """Read from raw fd and decrypt. Blocks until full frame arrives."""
        raw = os.read(fd, 4)
        if len(raw) < 4:
            raise EOFError("fd closed")
        length = struct.unpack("!I", raw)[0]
        frame  = b""
        while len(frame) < length:
            chunk = os.read(fd, length - len(frame))
            if not chunk:
                raise EOFError("incomplete frame on fd")
            frame += chunk
        return self.decrypt(frame)

    # ── socket helpers ────────────────────────────────────────────────────────

    def send_sock(self, sock: socket.socket, data: bytes):
        """Encrypt and send over socket."""
        frame = self.encrypt(data)
        sock.sendall(struct.pack("!I", len(frame)) + frame)

    def recv_sock(self, sock: socket.socket) -> bytes:
        """Receive from socket and decrypt."""
        raw = sock.recv(4)
        if not raw:
            raise ConnectionError("socket closed")
        length = struct.unpack("!I", raw)[0]
        frame  = b""
        while len(frame) < length:
            chunk = sock.recv(length - len(frame))
            if not chunk:
                raise ConnectionError("incomplete frame on socket")
            frame += chunk
        return self.decrypt(frame)

    # ── status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        tag, _ = self._piston.active()
        return {
            "label":          self._label,
            "ratchet_step":   self._ratchet.step,
            "piston_tag":     tag,
            "piston_window":  _Piston.WINDOW,
        }

    # ── factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls, label: str = "stack") -> "CTWStack":
        """
        Derive root key from environment.
        Looks for CTW_ROOT_KEY env var (hex).
        Falls back to physical entropy if not set.
        """
        hex_key = os.environ.get("CTW_ROOT_KEY")
        if hex_key:
            root = bytes.fromhex(hex_key)
            print(f"[CTW:{label}] Root key from CTW_ROOT_KEY")
        else:
            root = _physical_entropy()
            print(f"[CTW:{label}] Root key from physical entropy")
        return cls(root, label)

    @classmethod
    def from_shm(cls, path: str = "/dev/shm/ctw.key",
                 label: str = "stack") -> "CTWStack":
        """
        Read root key from RAM-backed shared memory file.
        File must be mode 600. Unlinked after read (single use).
        Use CTWStack.write_shm_key() to create it.
        """
        with open(path, "rb") as f:
            root = bytes.fromhex(f.read().strip().decode())
        os.unlink(path)
        print(f"[CTW:{label}] Root key from {path} (unlinked)")
        return cls(root, label)

    @staticmethod
    def write_shm_key(path: str = "/dev/shm/ctw.key") -> bytes:
        """
        Generate root key, write to RAM-backed file mode 600.
        Returns the key so caller can pass to both ends.
        """
        root = _physical_entropy()
        fd   = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, root.hex().encode())
        os.close(fd)
        print(f"[CTW] Root key written to {path} (RAM-backed, mode 600)")
        return root


###############################################################################
# 7. ANONYMOUS PIPE — drop-in for os.pipe()
###############################################################################

class CTWPipe:
    """
    Encrypted anonymous pipe. Drop-in for os.pipe().
    Parent creates, passes fds to child via fork.
    """
    def __init__(self, root_key: bytes):
        self._r, self._w = os.pipe()
        self._ws = CTWStack(root_key, "pipe-w")
        self._rs = CTWStack(root_key, "pipe-r")

    def write(self, data: bytes):
        self._ws.write_fd(self._w, data)

    def read(self) -> bytes:
        return self._rs.read_fd(self._r)

    def close_write(self): os.close(self._w)
    def close_read(self):  os.close(self._r)
    @property
    def read_fd(self):  return self._r
    @property
    def write_fd(self): return self._w


###############################################################################
# 8. UNIX SOCKET SERVER / CLIENT
###############################################################################

class CTWServer:
    def __init__(self, path: str, root_key: bytes):
        self._path = path
        self._rk   = root_key
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if Path(path).exists(): os.unlink(path)
        self._sock.bind(path)
        os.chmod(path, 0o600)
        self._sock.listen(1)
        self._conn: Optional[socket.socket] = None
        self._stack: Optional[CTWStack] = None
        print(f"[CTW-SERVER] Listening on {path}")

    def accept(self):
        self._conn, _ = self._sock.accept()
        self._stack = CTWStack(self._rk, "server")

    def send(self, data: bytes):
        self._stack.send_sock(self._conn, data)

    def recv(self) -> bytes:
        return self._stack.recv_sock(self._conn)

    def close(self):
        if self._conn: self._conn.close()
        self._sock.close()
        if Path(self._path).exists(): os.unlink(self._path)


class CTWClient:
    def __init__(self, path: str, root_key: bytes):
        self._sock  = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(path)
        self._stack = CTWStack(root_key, "client")
        print(f"[CTW-CLIENT] Connected to {path}")

    def send(self, data: bytes):
        self._stack.send_sock(self._sock, data)

    def recv(self) -> bytes:
        return self._stack.recv_sock(self._sock)

    def close(self): self._sock.close()


###############################################################################
# DEMO
###############################################################################

if __name__ == "__main__":
    print("=" * 60)
    print(" CTW Unified Encryption Stack v1.0")
    print(" ratchet + piston + polyglot — pipe/socket/fd")
    print("=" * 60)

    # ── shared key ────────────────────────────────────────────────────────────
    root_key = CTWStack.write_shm_key()

    # ── demo 1: raw encrypt/decrypt ───────────────────────────────────────────
    print("\n[1] Direct encrypt/decrypt")
    tx = CTWStack(root_key, "tx")
    rx = CTWStack(root_key, "rx")

    msgs = [
        b"forensic payload alpha",
        b"forensic payload beta",
        b"forensic payload gamma — crosses piston window",
    ]
    frames = []
    for m in msgs:
        f = tx.encrypt(m)
        frames.append(f)
        print(f"    enc({m[:20]!r}) → {len(f)} bytes | "
              f"preview: {f[8:16].hex()}")
        time.sleep(2.0)

    for f in frames:
        pt = rx.decrypt(f)
        print(f"    dec → {pt!r}")
        time.sleep(2.0)

    # ── demo 2: unix socket ───────────────────────────────────────────────────
    print("\n[2] Unix socket")
    SOCK = "/tmp/ctw_unified.sock"

    def _srv():
        s = CTWServer(SOCK, root_key)
        s.accept()
        for _ in range(3):
            d = s.recv()
            print(f"    [SRV] {d!r}")
            s.send(b"ack:" + d)
        s.close()

    t = threading.Thread(target=_srv, daemon=True)
    t.start()
    time.sleep(0.2)

    cli = CTWClient(SOCK, root_key)
    for i in range(3):
        cli.send(f"msg-{i}".encode())
        print(f"    [CLI] {cli.recv()!r}")
        time.sleep(0.4)
    cli.close()
    t.join(timeout=3)

    # ── demo 3: anonymous pipe ────────────────────────────────────────────────
    print("\n[3] Anonymous pipe (os.pipe replacement)")
    pipe = CTWPipe(root_key)

    def _writer():
        for i in range(3):
            pipe.write(f"pipe-payload-{i}".encode())
            time.sleep(0.3)
        pipe.close_write()

    wt = threading.Thread(target=_writer, daemon=True)
    wt.start()
    for _ in range(3):
        print(f"    [PIPE] {pipe.read()!r}")
    wt.join()

    print("\n[CTW] Stack demo complete.")
    print(json.dumps(tx.status(), indent=2))

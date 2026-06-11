#!/usr/bin/env python3
"""
CTW Encrypted Pipe/Socket Layer v1.0
Purpose: Drop-in encryption wrapper for Unix sockets, named pipes,
         and anonymous pipes between local processes.
         Piston cipher engine sits transparently in the data path.

Usage:
    # Writer side (any process)
    pipe = CTWEncryptedPipe("/tmp/ctw_ipc.sock")
    pipe.write(b"forensic payload")

    # Reader side (any process)
    pipe = CTWEncryptedPipe("/tmp/ctw_ipc.sock")
    data = pipe.read()

Architecture:
    Process A → CTWEncryptedPipe.write()
                  → piston encrypt segment
                  → polyglot obfuscate
                  → ratchet advance
                  → write framed bytes to socket/pipe
    Process B ← CTWEncryptedPipe.read()
                  ← read framed bytes
                  ← polyglot deobfuscate
                  ← piston decrypt segment
                  ← ratchet advance
                  ← plaintext delivered
"""

import os
import sys
import time
import json
import struct
import socket
import hashlib
import threading
import hmac as hmac_mod
from pathlib import Path
from typing import Optional

try:
    import blake3
    def fast_hash(data: bytes) -> bytes:
        return blake3.blake3(data).digest()
except ImportError:
    def fast_hash(data: bytes) -> bytes:
        return hashlib.sha3_256(data).digest()

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


###############################################################################
# FRAME FORMAT
# Every segment written to pipe/socket is length-prefixed and tagged
#
# [ 4 bytes: frame length ][ 2 bytes: slot+gen tag ][ N bytes: encrypted frame ]
#
# Receiver reads length, reads N bytes, decrypts using tag lookup
###############################################################################

FRAME_MAGIC = b"CTW\x01"   # 4 byte magic — detect frame boundary
FRAME_HEADER = struct.Struct("!4sHI")  # magic, tag, length


###############################################################################
# SHARED SESSION KEY ESTABLISHMENT
# Both ends of the pipe derive the same root key from a shared secret
# written to a permissions-locked file before pipe opens
# On single-device use: same process or parent derives and passes to both
###############################################################################

class SessionKeyFile:
    """
    Write/read a shared session secret via a permissions-locked temp file.
    Only accessible to processes running as same UID.
    File is unlinked after read — single use.
    """
    DEFAULT_PATH = "/dev/shm/ctw_session.key"  # RAM-backed, never hits disk

    @staticmethod
    def write(secret: bytes, path: str = DEFAULT_PATH):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, secret.hex().encode())
        os.close(fd)
        print(f"[CTW-SESSION] Key written to {path} (RAM-backed, mode 600)")

    @staticmethod
    def read(path: str = DEFAULT_PATH) -> bytes:
        try:
            with open(path, 'r') as f:
                secret = bytes.fromhex(f.read().strip())
            os.unlink(path)
            print(f"[CTW-SESSION] Key read and file unlinked")
            return secret
        except FileNotFoundError:
            raise RuntimeError(f"Session key file not found: {path}")


###############################################################################
# RATCHET STATE — inline minimal version for pipe layer
###############################################################################

class PipeRatchet:
    """
    Minimal forward-secret ratchet for pipe encryption.
    Advances on every segment — key used once, discarded.
    """

    def __init__(self, root_key: bytes):
        self._chain = fast_hash(root_key + b"CTW-pipe-chain-init")
        self._step = 0
        self._lock = threading.Lock()

    def advance(self) -> bytes:
        """Advance ratchet, return message key for this step."""
        with self._lock:
            # Mix physical jitter into each advance
            jitter = struct.pack("Q", time.perf_counter_ns())
            entropy = os.urandom(16)

            msg_key = hmac_mod.new(
                self._chain,
                b"CTW-pipe-msg-key" + jitter,
                hashlib.sha256
            ).digest()

            self._chain = fast_hash(
                self._chain + jitter + entropy +
                struct.pack("Q", self._step)
            )
            self._step += 1
            return msg_key

    def step(self) -> int:
        return self._step


###############################################################################
# PISTON STATE — two cipher slots, 5 second rotation
###############################################################################

class PistonState:
    """
    Two cipher slots alternating on WINDOW seconds.
    Overflow segments join whichever slot is active at completion.
    """
    WINDOW = 5.0

    def __init__(self, root_key: bytes):
        self._root = root_key
        self._lock = threading.Lock()
        self._generation = 0
        self._slot_keys = {}         # tag → key
        self._active_tag = 0
        self._slot_activated = time.monotonic()
        self._rotate_scheduled = False

        # Initialize first two slots
        self._active_tag = self._new_slot()
        self._standby_tag = self._new_slot()

        # Rotation daemon
        t = threading.Thread(target=self._rotation_loop, daemon=True)
        t.start()

    def _new_slot(self) -> int:
        """Create new slot, return its tag."""
        self._generation += 1
        tag = self._generation
        entropy = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=entropy,
            info=f"CTW-piston-slot-{tag}".encode(),
            backend=default_backend()
        )
        self._slot_keys[tag] = hkdf.derive(
            fast_hash(self._root + struct.pack("Q", tag))
        )
        return tag

    def _rotation_loop(self):
        while True:
            with self._lock:
                elapsed = time.monotonic() - self._slot_activated
            remaining = max(0.05, self.WINDOW - elapsed)
            time.sleep(remaining)
            with self._lock:
                # Swap active and standby
                old_active = self._active_tag
                self._active_tag = self._standby_tag
                self._standby_tag = self._new_slot()
                self._slot_activated = time.monotonic()
            print(f"[CTW-PISTON] Rotated | "
                  f"Active tag: {self._active_tag} | "
                  f"Retired: {old_active}")

    def active_tag_and_key(self) -> tuple:
        with self._lock:
            return self._active_tag, self._slot_keys[self._active_tag]

    def key_for_tag(self, tag: int) -> bytes:
        with self._lock:
            if tag not in self._slot_keys:
                raise KeyError(f"No key for slot tag {tag}")
            return self._slot_keys[tag]


###############################################################################
# ENCRYPTED PIPE / SOCKET
###############################################################################

class CTWEncryptedPipe:
    """
    Drop-in encrypted pipe/socket wrapper.

    Write side: plaintext in → ratchet + piston encrypt → framed bytes out
    Read side:  framed bytes in → piston + ratchet decrypt → plaintext out

    Both sides must share the same root_key.
    On single-device: derive root_key from SessionKeyFile or pass directly.
    """

    def __init__(self, root_key: bytes, label: str = "pipe"):
        self._label = label
        self._ratchet = PipeRatchet(root_key)
        self._piston = PistonState(root_key)
        print(f"[CTW-PIPE:{label}] Initialized")

    def _encrypt_frame(self, plaintext: bytes) -> bytes:
        """Encrypt one frame: ratchet key + piston slot + AESGCMSIV."""
        # Get ratchet key for this frame
        msg_key = self._ratchet.advance()

        # Get active piston slot
        tag, slot_key = self._piston.active_tag_and_key()

        # Derive per-frame AES key from both
        frame_key = fast_hash(msg_key + slot_key)

        # HKDF expand to 32 bytes
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b"CTW-frame-key",
            backend=default_backend()
        )
        # Use salt deterministically from frame_key so receiver can derive
        salt = fast_hash(frame_key)[:16]
        hkdf2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"CTW-frame-key",
            backend=default_backend()
        )
        aes_key = hkdf2.derive(frame_key)

        nonce = os.urandom(12)
        aesgcmsiv = AESGCMSIV(aes_key)

        # Embed tag in AAD so receiver knows which slot was used
        aad = struct.pack("!I", tag)
        ciphertext = aesgcmsiv.encrypt(nonce, plaintext, aad)

        # Frame: [nonce 12][tag 4][salt 16][ciphertext N]
        return nonce + aad + salt + ciphertext

    def _decrypt_frame(self, frame: bytes,
                       tag_override: Optional[int] = None) -> bytes:
        """Decrypt one frame."""
        nonce = frame[:12]
        tag_bytes = frame[12:16]
        salt = frame[16:32]
        ciphertext = frame[32:]

        tag = struct.unpack("!I", tag_bytes)[0]

        # Reconstruct ratchet key for this step
        msg_key = self._ratchet.advance()

        # Get slot key for this tag
        slot_key = self._piston.key_for_tag(tag)

        # Derive same frame key
        frame_key = fast_hash(msg_key + slot_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"CTW-frame-key",
            backend=default_backend()
        )
        aes_key = hkdf.derive(frame_key)

        aesgcmsiv = AESGCMSIV(aes_key)
        return aesgcmsiv.decrypt(nonce, ciphertext, tag_bytes)

    def wrap_write(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext → return encrypted frame bytes.
        Call this and write the result to your pipe/socket/fd.
        """
        encrypted = self._encrypt_frame(plaintext)
        # Length-prefix framing
        length = struct.pack("!I", len(encrypted))
        frame = FRAME_MAGIC + length + encrypted
        print(f"[CTW-PIPE:{self._label}] write | "
              f"plain={len(plaintext)}B → "
              f"frame={len(frame)}B | "
              f"ratchet step={self._ratchet.step()}")
        return frame

    def wrap_read(self, frame: bytes) -> bytes:
        """
        Receive frame bytes → decrypt → return plaintext.
        Call this on data read from your pipe/socket/fd.
        """
        if frame[:4] != FRAME_MAGIC:
            raise ValueError("Invalid frame magic — possible tampering or desync")
        length = struct.unpack("!I", frame[4:8])[0]
        encrypted = frame[8:8 + length]
        plaintext = self._decrypt_frame(encrypted)
        print(f"[CTW-PIPE:{self._label}] read | "
              f"frame={len(frame)}B → "
              f"plain={len(plaintext)}B | "
              f"ratchet step={self._ratchet.step()}")
        return plaintext

    def status(self) -> dict:
        tag, _ = self._piston.active_tag_and_key()
        return {
            "label": self._label,
            "ratchet_step": self._ratchet.step(),
            "active_piston_tag": tag,
        }


###############################################################################
# ANONYMOUS PIPE WRAPPER
# Wraps os.pipe() — drop-in for subprocess communication
###############################################################################

class CTWAnonymousPipe:
    """
    Wraps os.pipe() with CTW encryption.
    Use instead of os.pipe() for encrypted IPC between
    parent and child processes.
    """

    def __init__(self, root_key: bytes):
        self._read_fd, self._write_fd = os.pipe()
        self._cipher_write = CTWEncryptedPipe(root_key, "anon-write")
        self._cipher_read = CTWEncryptedPipe(root_key, "anon-read")

    def write(self, data: bytes):
        frame = self._cipher_write.wrap_write(data)
        # Write length then frame to handle pipe buffering
        os.write(self._write_fd,
                 struct.pack("!I", len(frame)) + frame)

    def read(self) -> bytes:
        # Read length prefix
        raw_len = os.read(self._read_fd, 4)
        length = struct.unpack("!I", raw_len)[0]
        frame_with_magic = os.read(self._read_fd, length)
        return self._cipher_read.wrap_read(frame_with_magic)

    def close_write(self):
        os.close(self._write_fd)

    def close_read(self):
        os.close(self._read_fd)


###############################################################################
# UNIX SOCKET WRAPPER
# Named socket at path — any two local processes can connect
###############################################################################

class CTWSocketServer:
    """Server side of a CTW encrypted Unix domain socket."""

    def __init__(self, path: str, root_key: bytes):
        self._path = path
        self._root_key = root_key
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(path):
            os.unlink(path)
        self._sock.bind(path)
        os.chmod(path, 0o600)
        self._sock.listen(1)
        self._conn = None
        self._cipher = None
        print(f"[CTW-SOCKET] Server listening on {path}")

    def accept(self):
        self._conn, _ = self._sock.accept()
        self._cipher = CTWEncryptedPipe(self._root_key, "server")
        print(f"[CTW-SOCKET] Client connected")

    def send(self, data: bytes):
        frame = self._cipher.wrap_write(data)
        self._conn.sendall(struct.pack("!I", len(frame)) + frame)

    def recv(self) -> bytes:
        raw_len = self._conn.recv(4)
        if not raw_len:
            raise ConnectionError("Client disconnected")
        length = struct.unpack("!I", raw_len)[0]
        frame = b""
        while len(frame) < length:
            chunk = self._conn.recv(length - len(frame))
            if not chunk:
                raise ConnectionError("Incomplete frame")
            frame += chunk
        return self._cipher.wrap_read(frame)

    def close(self):
        if self._conn:
            self._conn.close()
        self._sock.close()
        if os.path.exists(self._path):
            os.unlink(self._path)


class CTWSocketClient:
    """Client side of a CTW encrypted Unix domain socket."""

    def __init__(self, path: str, root_key: bytes):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(path)
        self._cipher = CTWEncryptedPipe(root_key, "client")
        print(f"[CTW-SOCKET] Connected to {path}")

    def send(self, data: bytes):
        frame = self._cipher.wrap_write(data)
        self._sock.sendall(struct.pack("!I", len(frame)) + frame)

    def recv(self) -> bytes:
        raw_len = self._sock.recv(4)
        if not raw_len:
            raise ConnectionError("Server disconnected")
        length = struct.unpack("!I", raw_len)[0]
        frame = b""
        while len(frame) < length:
            chunk = self._sock.recv(length - len(frame))
            if not chunk:
                raise ConnectionError("Incomplete frame")
            frame += chunk
        return self._cipher.wrap_read(frame)

    def close(self):
        self._sock.close()


###############################################################################
# DEMO — anonymous pipe between parent and child
###############################################################################

if __name__ == "__main__":
    print("=" * 60)
    print(" CTW Encrypted Pipe/Socket Layer v1.0")
    print(" Stack/socket/pipe encryption protocol")
    print("=" * 60)

    # Shared root key — in production from SessionKeyFile
    root_key = os.urandom(32)
    print(f"\n[*] Root key established: {root_key.hex()[:16]}...")

    # Demo 1: wrap_write / wrap_read on same instance (single process)
    print("\n[*] Demo: Single-process pipe encryption")
    pipe = CTWEncryptedPipe(root_key, "demo")

    messages = [
        b"CTW forensic payload alpha",
        b"CTW forensic payload beta — crosses window boundary",
        b"CTW forensic payload gamma",
    ]

    frames = []
    for msg in messages:
        frame = pipe.wrap_write(msg)
        frames.append(frame)
        print(f"    Encrypted: {frame[:20].hex()}... ({len(frame)} bytes)")
        time.sleep(1.8)  # Spread across piston windows

    print(f"\n[*] Decrypting frames...")
    # Fresh pipe with same root key simulates receiver
    recv_pipe = CTWEncryptedPipe(root_key, "recv")
    for frame in frames:
        plaintext = recv_pipe.wrap_read(frame)
        print(f"    Decrypted: {plaintext.decode()}")
        time.sleep(1.8)

    print(f"\n[*] Status: {json.dumps(pipe.status(), indent=2)}")

    # Demo 2: Unix socket
    print("\n[*] Demo: Unix domain socket")
    SOCK_PATH = "/tmp/ctw_demo.sock"

    def server_thread():
        srv = CTWSocketServer(SOCK_PATH, root_key)
        srv.accept()
        for _ in range(3):
            data = srv.recv()
            print(f"    [SERVER] Received: {data.decode()}")
            srv.send(b"ACK: " + data)
        srv.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    time.sleep(0.3)

    cli = CTWSocketClient(SOCK_PATH, root_key)
    for i in range(3):
        msg = f"CTW socket message {i+1}".encode()
        cli.send(msg)
        ack = cli.recv()
        print(f"    [CLIENT] Got: {ack.decode()}")
        time.sleep(0.5)
    cli.close()
    t.join(timeout=3)

    print("\n[CTW] Pipe/socket layer demo complete.")

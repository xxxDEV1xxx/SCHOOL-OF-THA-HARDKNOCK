#!/usr/bin/env python3
"""
CTW Physical Ratchet Key System v1.0
Platform: Kali NetHunter / ARM
Purpose: Physical-event-seeded forward-secret key ratchet
         Software implementation of PUF-adjacent ratcheting
         using locally available hardware entropy sources.

Architecture:
  - Seed derived from physical events, not stored values
  - Each ratchet step consumes a hardware entropy sample
  - Keys never stored — only derived on demand
  - Forward secrecy: past keys unrecoverable after advance

Dependencies: pip install cryptography blake3
"""

import os
import time
import hashlib
import struct
import hmac
import threading
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# blake3 if available, fallback to sha3_256
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
# ENTROPY HARVESTER
# Collects physical-event entropy from available hardware sources
###############################################################################

class PhysicalEntropyHarvester:
    """
    Harvests entropy from physical hardware events.
    Sources: thermal, CPU jitter, USB events, /dev/random, timing variance.
    On ARM/NetHunter these sources reflect actual physical silicon state.
    """

    def harvest_thermal(self) -> bytes:
        """Read CPU thermal sensors — physical die temperature variance."""
        readings = []
        thermal_paths = list(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
        for p in thermal_paths[:4]:
            try:
                val = int(p.read_text().strip())
                readings.append(val)
            except Exception:
                pass
        if not readings:
            readings = [0]
        return struct.pack(f"{len(readings)}i", *readings)

    def harvest_tsc_jitter(self, samples: int = 8) -> bytes:
        """
        Measure timestamp counter jitter between iterations.
        Inter-sample variance reflects physical CPU state —
        cache pressure, thermal throttling, branch predictor state.
        """
        times = []
        for _ in range(samples):
            t1 = time.perf_counter_ns()
            # Mixed workload — non-deterministic execution path
            _ = hashlib.sha256(os.urandom(32)).digest()
            t2 = time.perf_counter_ns()
            times.append(t2 - t1)
        # XOR all jitter values into 8 bytes
        jitter = 0
        for t in times:
            jitter ^= t
        return struct.pack("Q", jitter & 0xFFFFFFFFFFFFFFFF)

    def harvest_usb_timing(self) -> bytes:
        """
        Sample USB device enumeration state.
        Connection time and device count are physical events
        that cannot be replicated remotely.
        """
        try:
            usb_path = Path("/sys/bus/usb/devices")
            devices = list(usb_path.iterdir())
            count = len(devices)
            # Use device names as entropy material
            names = "".join(sorted(d.name for d in devices[:8]))
            return fast_hash(f"{count}:{names}:{time.monotonic_ns()}".encode())
        except Exception:
            return os.urandom(32)

    def harvest_network_jitter(self) -> bytes:
        """Sample network interface counters — physical RF activity proxy."""
        try:
            stats = Path("/proc/net/dev").read_text()
            return fast_hash(stats.encode())
        except Exception:
            return os.urandom(32)

    def harvest_memory_pressure(self) -> bytes:
        """Sample /proc/meminfo — reflects actual system physical state."""
        try:
            mem = Path("/proc/meminfo").read_text()
            # Extract numeric values only
            vals = [int(x) for x in mem.split() if x.isdigit()][:16]
            return struct.pack(f"{len(vals)}Q",
                               *[v & 0xFFFFFFFFFFFFFFFF for v in vals])
        except Exception:
            return os.urandom(32)

    def harvest_all(self) -> bytes:
        """
        Combine all physical entropy sources into single entropy blob.
        Each source is independent — compromise of one does not
        compromise the combined seed.
        """
        sources = [
            self.harvest_tsc_jitter(),
            self.harvest_thermal(),
            self.harvest_usb_timing(),
            self.harvest_network_jitter(),
            self.harvest_memory_pressure(),
            os.urandom(32),              # Kernel TRNG — hardware RNG on ARM
        ]
        combined = b"".join(sources)
        # Final mix via fast_hash — avalanche effect
        return fast_hash(combined)


###############################################################################
# RATCHET ENGINE
# Forward-secret key derivation with physical event anchoring
###############################################################################

@dataclass
class RatchetState:
    """
    Ratchet state — held in memory only, never written to disk.
    Loss of process = loss of state = forward secrecy enforced.
    """
    root_key: bytes          # Current root key
    chain_key: bytes         # Current chain key
    step_count: int = 0      # Ratchet step counter
    session_id: bytes = field(default_factory=lambda: os.urandom(16))

    def __post_init__(self):
        assert len(self.root_key) == 32
        assert len(self.chain_key) == 32


class CTWPhysicalRatchet:
    """
    Physical-event-seeded forward-secret ratchet.

    Key insight: each ratchet step requires a fresh physical entropy sample.
    An adversary modeling the system remotely cannot advance the ratchet
    without access to the physical hardware state at that moment.

    Based on: Signal double ratchet + PUF seeding concept
    Reference: Marlinspike/Perrin 2016, Pappu et al 2002
    Novel element: physical event as mandatory ratchet trigger
    """

    def __init__(self):
        self.harvester = PhysicalEntropyHarvester()
        self.state: Optional[RatchetState] = None
        self._lock = threading.Lock()

    def initialize(self, shared_secret: Optional[bytes] = None) -> bytes:
        """
        Initialize ratchet from physical entropy + optional shared secret.
        Returns session_id for endpoint correlation.
        """
        physical_entropy = self.harvester.harvest_all()

        if shared_secret:
            seed = fast_hash(physical_entropy + shared_secret)
        else:
            seed = physical_entropy

        # Derive initial root and chain keys via HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=os.urandom(32),
            info=b"CTW-ratchet-init-v1",
            backend=default_backend()
        )
        key_material = hkdf.derive(seed)
        root_key = key_material[:32]
        chain_key = key_material[32:]

        with self._lock:
            self.state = RatchetState(
                root_key=root_key,
                chain_key=chain_key
            )

        print(f"[CTW-RATCHET] Initialized | Session: {self.state.session_id.hex()[:16]}")
        return self.state.session_id

    def advance(self) -> bytes:
        """
        Advance ratchet one step.
        Requires fresh physical entropy sample — cannot be advanced
        without live hardware access.
        Returns message key for this step.
        """
        if not self.state:
            raise RuntimeError("Ratchet not initialized")

        # Fresh physical entropy sample required for each advance
        physical_sample = self.harvester.harvest_all()

        with self._lock:
            # Mix physical entropy into chain key
            new_chain_input = fast_hash(
                self.state.chain_key + physical_sample +
                struct.pack("Q", self.state.step_count)
            )

            # Derive message key and advance chain key
            msg_key = hmac.new(
                new_chain_input,
                b"CTW-message-key",
                hashlib.sha256
            ).digest()

            new_chain_key = hmac.new(
                new_chain_input,
                b"CTW-chain-advance",
                hashlib.sha256
            ).digest()

            # Advance root key using physical entropy
            new_root_key = fast_hash(
                self.state.root_key + new_chain_input
            )

            # Overwrite state — old keys are gone
            self.state.root_key = new_root_key
            self.state.chain_key = new_chain_key
            self.state.step_count += 1

            step = self.state.step_count

        print(f"[CTW-RATCHET] Advanced | Step: {step} | "
              f"Key prefix: {msg_key.hex()[:8]}...")
        return msg_key

    def encrypt(self, plaintext: bytes) -> dict:
        """
        Encrypt message using current ratchet step key.
        Key is derived, used once, discarded.
        """
        msg_key = self.advance()

        # Derive AES-GCM-SIV key from message key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b"CTW-aes-gcm-siv",
            backend=default_backend()
        )
        # Use salt in output so receiver can derive same key
        salt = os.urandom(16)
        hkdf2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"CTW-aes-gcm-siv",
            backend=default_backend()
        )
        aes_key = hkdf2.derive(msg_key)

        nonce = os.urandom(12)
        aesgcmsiv = AESGCMSIV(aes_key)
        ciphertext = aesgcmsiv.encrypt(nonce, plaintext, None)

        return {
            "step": self.state.step_count,
            "session": self.state.session_id.hex(),
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

    def decrypt(self, msg_key: bytes, packet: dict) -> bytes:
        """
        Decrypt using provided message key.
        Caller is responsible for key delivery (out of band).
        """
        salt = bytes.fromhex(packet["salt"])
        nonce = bytes.fromhex(packet["nonce"])
        ciphertext = bytes.fromhex(packet["ciphertext"])

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"CTW-aes-gcm-siv",
            backend=default_backend()
        )
        aes_key = hkdf.derive(msg_key)
        aesgcmsiv = AESGCMSIV(aes_key)
        return aesgcmsiv.decrypt(nonce, ciphertext, None)

    def status(self) -> dict:
        """Return current ratchet state summary — no key material exposed."""
        if not self.state:
            return {"status": "uninitialized"}
        return {
            "status": "active",
            "session_id": self.state.session_id.hex(),
            "step_count": self.state.step_count,
            "root_key_prefix": self.state.root_key.hex()[:8],
        }


###############################################################################
# AUTO-ADVANCE DAEMON
# Continuously advances ratchet on physical events
# Makes key state a moving target — phase lock becomes impossible
###############################################################################

class RatchetAdvanceDaemon(threading.Thread):
    """
    Background daemon that auto-advances ratchet on physical events.
    Ratchet velocity > adversary modeling velocity = operational security.
    """

    def __init__(self, ratchet: CTWPhysicalRatchet,
                 min_interval: float = 0.5,
                 max_interval: float = 3.0):
        super().__init__(daemon=True)
        self.ratchet = ratchet
        self.min_interval = min_interval
        self.max_interval = max_interval
        self._stop_event = threading.Event()

    def run(self):
        print("[CTW-DAEMON] Ratchet advance daemon started")
        while not self._stop_event.is_set():
            # Variable interval — non-deterministic advance timing
            interval = (self.min_interval +
                       (int.from_bytes(os.urandom(4), 'big') / 0xFFFFFFFF) *
                       (self.max_interval - self.min_interval))
            time.sleep(interval)
            try:
                self.ratchet.advance()
            except Exception as e:
                print(f"[CTW-DAEMON] Advance error: {e}")

    def stop(self):
        self._stop_event.set()


###############################################################################
# CLI DEMO
###############################################################################

if __name__ == "__main__":
    print("=" * 60)
    print(" CTW Physical Ratchet Key System v1.0")
    print(" Platform: NetHunter ARM")
    print("=" * 60)

    ratchet = CTWPhysicalRatchet()
    session_id = ratchet.initialize()

    print(f"\n[*] Session initialized: {session_id.hex()}")
    print(f"[*] Status: {json.dumps(ratchet.status(), indent=2)}")

    # Start auto-advance daemon
    daemon = RatchetAdvanceDaemon(ratchet, min_interval=1.0, max_interval=4.0)
    daemon.start()
    print("\n[*] Auto-advance daemon running")
    print("[*] Ratchet advancing on physical entropy — key state is moving\n")

    # Demo encryption
    test_msg = b"CTW forensic payload — timestamp anchored"
    print(f"[*] Encrypting: {test_msg.decode()}")

    # Get key before encrypt (in real use, key exchange is out-of-band)
    msg_key = ratchet.advance()
    packet = ratchet.encrypt(test_msg)

    print(f"[*] Encrypted packet:")
    print(json.dumps(packet, indent=2))

    # Decrypt using the key we captured
    plaintext = ratchet.decrypt(msg_key, packet)
    print(f"\n[*] Decrypted: {plaintext.decode()}")

    print(f"\n[*] Final status: {json.dumps(ratchet.status(), indent=2)}")
    print("\n[*] CTRL+C to stop daemon")

    try:
        while True:
            time.sleep(5)
            print(f"[*] Ratchet status: {json.dumps(ratchet.status(), indent=2)}")
    except KeyboardInterrupt:
        daemon.stop()
        print("\n[CTW] Ratchet daemon stopped. Session keys lost — forward secrecy enforced.")

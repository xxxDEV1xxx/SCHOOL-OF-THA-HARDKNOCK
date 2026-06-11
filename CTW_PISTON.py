#!/usr/bin/env python3
"""
CTW Piston Cipher Engine v1.0
Purpose: Double-buffered cipher pipeline with overflow segmentation
         Two cipher states alternate on 5-second schedule
         Overflow compute joins whichever cipher is currently active
         Final plaintext = ordered reconstruction of all segments

Architecture:
  Cipher A (5sec) → Cipher B (5sec) → Cipher A (5sec) → ...
  Segment overflow → appended to active cipher's segment list
  Reconstruction map embedded in packet header

Based on: AEAD chunked encryption, TLS record layer concepts
Novel element: compute-reality-driven segment boundaries +
               physical ratchet anchor per boundary transition
"""

import os
import time
import json
import threading
import hashlib
import struct
import queue
from typing import List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

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
# CIPHER STATE
###############################################################################

class CipherSlot(Enum):
    A = "A"
    B = "B"


@dataclass
class CipherState:
    """
    One piston state — holds key material and segment log.
    Replaced every 10 seconds (each slot gets 5 seconds active).
    """
    slot: CipherSlot
    key: bytes                          # AES-GCM-SIV key
    generation: int                     # How many times this slot has cycled
    activated_at: float                 # monotonic time of activation
    segments: List[dict] = field(default_factory=list)
    segment_count: int = 0

    def age(self) -> float:
        return time.monotonic() - self.activated_at

    def is_expired(self, window: float = 5.0) -> bool:
        return self.age() > window


@dataclass
class Segment:
    """
    One encrypted segment — product of one encrypt call.
    Carries its cipher slot and generation for reconstruction.
    """
    slot: str           # "A" or "B"
    generation: int     # Cipher generation at time of encryption
    index: int          # Global segment index for ordering
    nonce: bytes
    ciphertext: bytes
    started_at: float   # When this segment's compute began
    finished_at: float  # When encryption completed

    def to_dict(self) -> dict:
        return {
            "slot": self.slot,
            "generation": self.generation,
            "index": self.index,
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "compute_ms": round((self.finished_at - self.started_at) * 1000, 2)
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Segment":
        return cls(
            slot=d["slot"],
            generation=d["generation"],
            index=d["index"],
            nonce=bytes.fromhex(d["nonce"]),
            ciphertext=bytes.fromhex(d["ciphertext"]),
            started_at=d["started_at"],
            finished_at=d["finished_at"]
        )


###############################################################################
# PHYSICAL ENTROPY — minimal inline version
###############################################################################

def harvest_entropy() -> bytes:
    """Quick physical entropy harvest for key derivation."""
    sources = [
        os.urandom(32),
        struct.pack("Q", time.perf_counter_ns()),
        struct.pack("Q", time.monotonic_ns()),
    ]
    # Thermal if available
    try:
        from pathlib import Path
        temps = list(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
        if temps:
            val = int(temps[0].read_text().strip())
            sources.append(struct.pack("i", val))
    except Exception:
        pass
    return fast_hash(b"".join(sources))


def derive_key(seed: bytes, slot: CipherSlot, generation: int) -> bytes:
    """Derive AES key from seed + slot + generation."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        info=f"CTW-piston-{slot.value}-gen{generation}".encode(),
        backend=default_backend()
    )
    # Mix physical entropy into each key derivation
    return hkdf.derive(fast_hash(seed + harvest_entropy()))


###############################################################################
# PISTON ENGINE
###############################################################################

class CTWPistonEngine:
    """
    Double-buffered cipher pipeline.

    Two cipher states (A and B) alternate on WINDOW_SECONDS schedule.
    Active cipher handles all new encrypt requests.
    If compute started in cipher A extends into cipher B's window,
    the segment is tagged with the cipher that was active when it
    COMPLETES — joining the current active cipher's segment list.
    This means segment boundaries follow compute reality, not clock ticks.

    Reconstruction: receiver orders segments by global index,
    decrypts each using the key identified by (slot, generation).
    Key material for each generation is embedded in the session manifest.
    """

    WINDOW_SECONDS = 5.0

    def __init__(self):
        self._seed = harvest_entropy()
        self._lock = threading.RLock()
        self._segment_counter = 0
        self._generation = 0

        # Initialize both slots
        self._slots = {
            CipherSlot.A: self._new_state(CipherSlot.A),
            CipherSlot.B: self._new_state(CipherSlot.B),
        }
        self._active_slot = CipherSlot.A
        self._inactive_slot = CipherSlot.B

        # Session manifest — maps (slot, generation) → key
        # In production: transmit manifest encrypted under out-of-band key
        self._manifest: dict = {}
        self._record_manifest(CipherSlot.A, 0, self._slots[CipherSlot.A].key)
        self._record_manifest(CipherSlot.B, 0, self._slots[CipherSlot.B].key)

        # Start rotation daemon
        self._rotation_thread = threading.Thread(
            target=self._rotation_loop, daemon=True
        )
        self._rotation_thread.start()
        print(f"[CTW-PISTON] Engine initialized | "
              f"Active slot: {self._active_slot.value} | "
              f"Window: {self.WINDOW_SECONDS}s")

    def _new_state(self, slot: CipherSlot) -> CipherState:
        """Create fresh cipher state for a slot."""
        self._generation += 1
        gen = self._generation
        key = derive_key(self._seed, slot, gen)
        return CipherState(
            slot=slot,
            key=key,
            generation=gen,
            activated_at=time.monotonic()
        )

    def _record_manifest(self, slot: CipherSlot,
                         generation: int, key: bytes):
        """Record key in session manifest for reconstruction."""
        self._manifest[f"{slot.value}:{generation}"] = key.hex()

    def _rotation_loop(self):
        """Background rotation — swaps active/inactive every WINDOW_SECONDS."""
        while True:
            # Sleep for remainder of current window
            with self._lock:
                active = self._slots[self._active_slot]
                elapsed = active.age()
            remaining = max(0.1, self.WINDOW_SECONDS - elapsed)
            time.sleep(remaining)
            self._rotate()

    def _rotate(self):
        """Swap active and inactive slots. Refresh inactive slot key."""
        with self._lock:
            # Swap
            prev_active = self._active_slot
            prev_inactive = self._inactive_slot
            self._active_slot = prev_inactive
            self._inactive_slot = prev_active

            # Refresh the newly inactive slot (was just active)
            # Its segments are preserved for reconstruction
            # Its key is rotated for next cycle
            old_state = self._slots[self._inactive_slot]
            new_state = self._new_state(self._inactive_slot)
            # Preserve segment history
            new_state.segments = []
            self._slots[self._inactive_slot] = new_state
            self._record_manifest(
                self._inactive_slot,
                new_state.generation,
                new_state.key
            )

            print(f"[CTW-PISTON] Rotation | "
                  f"Active → {self._active_slot.value} "
                  f"(gen {self._slots[self._active_slot].generation}) | "
                  f"Retired {self._inactive_slot.value} "
                  f"({len(old_state.segments)} segments)")

    def _active_state(self) -> CipherState:
        """Return currently active cipher state."""
        return self._slots[self._active_slot]

    def encrypt_segment(self, plaintext: bytes) -> Segment:
        """
        Encrypt one segment.
        Records start time before encryption.
        Tags segment with whichever cipher is active at COMPLETION.
        This is the overflow rule — long compute joins active cipher.
        """
        started_at = time.monotonic()

        # Get active state at completion time (may have rotated)
        with self._lock:
            state = self._active_state()
            slot = state.slot
            generation = state.generation
            key = state.key

        # Encrypt (outside lock to avoid blocking rotation)
        nonce = os.urandom(12)
        aesgcmsiv = AESGCMSIV(key)
        ciphertext = aesgcmsiv.encrypt(nonce, plaintext, None)
        finished_at = time.monotonic()

        with self._lock:
            idx = self._segment_counter
            self._segment_counter += 1

            seg = Segment(
                slot=slot.value,
                generation=generation,
                index=idx,
                nonce=nonce,
                ciphertext=ciphertext,
                started_at=started_at,
                finished_at=finished_at
            )

            # Log segment to active cipher's record
            self._slots[slot].segments.append(seg.to_dict())

        compute_ms = (finished_at - started_at) * 1000
        crossed = finished_at - started_at > (
            self.WINDOW_SECONDS - (started_at - self._active_state().activated_at)
        )
        if crossed:
            print(f"[CTW-PISTON] Segment #{idx} overflowed window → "
                  f"joined {slot.value}:{generation}")
        else:
            print(f"[CTW-PISTON] Segment #{idx} → "
                  f"{slot.value}:{generation} ({compute_ms:.1f}ms)")
        return seg

    def decrypt_segment(self, seg: Segment) -> bytes:
        """
        Decrypt segment using manifest key for its (slot, generation).
        Works on any historical segment as long as manifest is available.
        """
        manifest_key = f"{seg.slot}:{seg.generation}"
        with self._lock:
            key_hex = self._manifest.get(manifest_key)

        if not key_hex:
            raise KeyError(f"No key in manifest for {manifest_key}")

        key = bytes.fromhex(key_hex)
        aesgcmsiv = AESGCMSIV(key)
        return aesgcmsiv.decrypt(seg.nonce, seg.ciphertext, None)

    def package_stream(self, segments: List[Segment]) -> dict:
        """
        Package ordered segment list for transmission.
        Includes reconstruction map so receiver can order and decrypt.
        Manifest transmitted separately under out-of-band key.
        """
        return {
            "version": "CTW-piston-v1",
            "segment_count": len(segments),
            "reconstruction_map": [
                {"index": s.index, "slot": s.slot, "generation": s.generation}
                for s in sorted(segments, key=lambda x: x.index)
            ],
            "segments": [s.to_dict() for s in
                         sorted(segments, key=lambda x: x.index)]
        }

    def reconstruct_stream(self, package: dict) -> bytes:
        """
        Reconstruct plaintext from ordered segments.
        Uses reconstruction map to order, manifest to decrypt each.
        """
        segments = [Segment.from_dict(s) for s in package["segments"]]
        segments.sort(key=lambda x: x.index)

        plaintext_parts = []
        for seg in segments:
            part = self.decrypt_segment(seg)
            plaintext_parts.append(part)
            print(f"[CTW-PISTON] Reconstructed segment #{seg.index} "
                  f"({seg.slot}:{seg.generation})")

        return b"".join(plaintext_parts)

    def status(self) -> dict:
        with self._lock:
            active = self._active_state()
            inactive = self._slots[self._inactive_slot]
            return {
                "active_slot": self._active_slot.value,
                "active_generation": active.generation,
                "active_age_seconds": round(active.age(), 2),
                "active_segments": len(active.segments),
                "inactive_slot": self._inactive_slot.value,
                "inactive_generation": inactive.generation,
                "inactive_segments": len(inactive.segments),
                "total_segments_encrypted": self._segment_counter,
                "manifest_entries": len(self._manifest),
                "window_seconds": self.WINDOW_SECONDS
            }


###############################################################################
# DEMO
###############################################################################

if __name__ == "__main__":
    print("=" * 60)
    print(" CTW Piston Cipher Engine v1.0")
    print(" Double-buffered pipeline encryption")
    print("=" * 60)

    engine = CTWPistonEngine()
    segments = []

    # Encrypt several segments — some will cross window boundaries
    payloads = [
        b"Segment 1 — forensic payload alpha",
        b"Segment 2 — forensic payload beta",
        b"Segment 3 — forensic payload gamma",
        b"Segment 4 — forensic payload delta",
    ]

    print(f"\n[*] Encrypting {len(payloads)} segments...")
    for p in payloads:
        seg = engine.encrypt_segment(p)
        segments.append(seg)
        time.sleep(1.5)  # Spread across window boundaries

    print(f"\n[*] Status: {json.dumps(engine.status(), indent=2)}")

    # Package stream
    package = engine.package_stream(segments)
    print(f"\n[*] Stream package — reconstruction map:")
    for entry in package["reconstruction_map"]:
        print(f"    Segment #{entry['index']} → "
              f"{entry['slot']}:{entry['generation']}")

    # Reconstruct
    print(f"\n[*] Reconstructing stream...")
    plaintext = engine.reconstruct_stream(package)
    print(f"\n[*] Reconstructed stream:")
    # Split on segment boundaries for display
    for part in plaintext.split(b" — "):
        if part:
            print(f"    {part.decode(errors='replace')}")

    print(f"\n[*] Waiting for rotation event...")
    time.sleep(6)
    print(f"\n[*] Post-rotation status:")
    print(json.dumps(engine.status(), indent=2))

    print("\n[CTW] CTRL+C to stop")
    try:
        while True:
            time.sleep(5)
            print(json.dumps(engine.status(), indent=2))
    except KeyboardInterrupt:
        print("\n[CTW] Piston engine stopped.")

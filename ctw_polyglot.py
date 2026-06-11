#!/usr/bin/env python3
"""
CTW Polyglot Cipher Layer v1.0
Purpose: Unicode polyalphabet substitution obfuscation layer
         Sits on top of AES-GCM-SIV ratchet encryption
         Rotates through language character sets on ratchet schedule

Architecture:
  Plaintext → AES-GCM-SIV (strong crypto) → Polyglot substitution (obfuscation)
  Ciphertext looks like random multilingual text noise
  Substitution map rotates every N seconds via physical ratchet seed

Honest assessment:
  Substitution alone is NOT cryptographically strong
  Combined with AES layer it adds obfuscation against pattern matchers
  looking for AES output signatures
"""

import os
import time
import json
import random
import hashlib
import struct
import threading
from typing import List, Dict, Tuple

try:
    import blake3
    def fast_hash(data: bytes) -> bytes:
        return blake3.blake3(data).digest()
except ImportError:
    def fast_hash(data: bytes) -> bytes:
        return hashlib.sha3_256(data).digest()


###############################################################################
# UNICODE CHARACTER POOLS
# Each language pack contributes characters to the substitution alphabet
# 100+ scripts available in Unicode — we use a representative set
###############################################################################

LANGUAGE_PACKS = {
    "latin_ext":     list(range(0x00C0, 0x00FF)),   # Extended Latin
    "greek":         list(range(0x0391, 0x03C9)),   # Greek
    "cyrillic":      list(range(0x0410, 0x044F)),   # Cyrillic
    "armenian":      list(range(0x0531, 0x0556)),   # Armenian
    "georgian":      list(range(0x10D0, 0x10FA)),   # Georgian
    "hebrew":        list(range(0x05D0, 0x05EA)),   # Hebrew
    "arabic":        list(range(0x0621, 0x064A)),   # Arabic
    "devanagari":    list(range(0x0900, 0x0963)),   # Devanagari
    "bengali":       list(range(0x0985, 0x09B9)),   # Bengali
    "gurmukhi":      list(range(0x0A05, 0x0A39)),   # Gurmukhi
    "gujarati":      list(range(0x0A85, 0x0AB9)),   # Gujarati
    "tamil":         list(range(0x0B85, 0x0BB9)),   # Tamil
    "telugu":        list(range(0x0C05, 0x0C39)),   # Telugu
    "kannada":       list(range(0x0C85, 0x0CB9)),   # Kannada
    "malayalam":     list(range(0x0D05, 0x0D39)),   # Malayalam
    "thai":          list(range(0x0E01, 0x0E2E)),   # Thai
    "lao":           list(range(0x0E81, 0x0EAE)),   # Lao
    "tibetan":       list(range(0x0F40, 0x0F6C)),   # Tibetan
    "myanmar":       list(range(0x1000, 0x1021)),   # Myanmar
    "khmer":         list(range(0x1780, 0x17B3)),   # Khmer
    "mongolian":     list(range(0x1820, 0x1877)),   # Mongolian
    "hiragana":      list(range(0x3041, 0x3096)),   # Hiragana
    "katakana":      list(range(0x30A1, 0x30F6)),   # Katakana
    "hangul":        list(range(0xAC00, 0xAC60)),   # Hangul subset
    "cjk_unified":   list(range(0x4E00, 0x4E60)),   # CJK subset
    "ethiopic":      list(range(0x1200, 0x1248)),   # Ethiopic
    "cherokee":      list(range(0x13A0, 0x13F5)),   # Cherokee
    "ogham":         list(range(0x1680, 0x169C)),   # Ogham
    "runic":         list(range(0x16A0, 0x16EA)),   # Runic
    "gothic":        list(range(0x10330, 0x1034A)), # Gothic
    "linear_b":      list(range(0x10000, 0x1000C)), # Linear B
    "coptic":        list(range(0x03E2, 0x03EF)),   # Coptic
    "glagolitic":    list(range(0x2C00, 0x2C2E)),   # Glagolitic
    "nko":           list(range(0x07C0, 0x07EA)),   # NKo
    "samaritan":     list(range(0x0800, 0x082D)),   # Samaritan
    "sinhala":       list(range(0x0D85, 0x0DC6)),   # Sinhala
    "lisu":          list(range(0xA4D0, 0xA4FD)),   # Lisu
    "vai":           list(range(0xA500, 0xA60C)),   # Vai
    "bamum":         list(range(0xA6A0, 0xA6EF)),   # Bamum
    "javanese":      list(range(0xA984, 0xA9B2)),   # Javanese
}

PACK_NAMES = list(LANGUAGE_PACKS.keys())


###############################################################################
# SUBSTITUTION MAP GENERATOR
# Seeded from ratchet key — deterministic given seed, unpredictable without
###############################################################################

class SubstitutionMapGenerator:
    """
    Generates byte→unicode substitution maps from a seed.
    Two endpoints with the same ratchet seed produce the same map.
    Anyone without the seed sees random unicode noise.
    """

    def __init__(self, pack_rotation_seed: bytes):
        self.seed = pack_rotation_seed

    def _select_packs(self, n_packs: int = 8) -> List[str]:
        """Select N language packs deterministically from seed."""
        rng = random.Random(int.from_bytes(self.seed[:8], 'big'))
        return rng.sample(PACK_NAMES, min(n_packs, len(PACK_NAMES)))

    def _build_char_pool(self, packs: List[str]) -> List[int]:
        """Build unified character pool from selected packs."""
        pool = []
        for pack in packs:
            pool.extend(LANGUAGE_PACKS[pack])
        # Deduplicate and shuffle deterministically
        pool = list(set(pool))
        rng = random.Random(int.from_bytes(self.seed[8:16], 'big'))
        rng.shuffle(pool)
        return pool

    def generate(self) -> Tuple[Dict[int, str], Dict[str, int]]:
        """
        Generate forward and reverse substitution maps.
        Maps each byte value (0-255) to a unicode character.
        Returns (encode_map, decode_map).
        """
        packs = self._select_packs(8)
        pool = self._build_char_pool(packs)

        # Ensure pool is large enough for 256 byte values
        while len(pool) < 256:
            # Extend with modified codepoints if needed
            pool.extend([p + 0x10000 for p in pool[:256 - len(pool)]])

        pool = pool[:256]

        # Shuffle pool order using full seed
        rng = random.Random(int.from_bytes(self.seed[16:24], 'big'))
        rng.shuffle(pool)

        encode_map = {}
        decode_map = {}
        for byte_val in range(256):
            char = chr(pool[byte_val])
            encode_map[byte_val] = char
            decode_map[char] = byte_val

        return encode_map, decode_map

    def pack_names_used(self) -> List[str]:
        return self._select_packs(8)


###############################################################################
# POLYGLOT CIPHER ENGINE
# Combines AES-GCM-SIV + rotating unicode substitution
###############################################################################

class CTWPolyglotCipher:
    """
    Two-layer cipher:
    Layer 1: AES-GCM-SIV via ratchet key (cryptographic strength)
    Layer 2: Unicode polyalphabet substitution (obfuscation)

    Rotation: substitution map changes every ROTATION_INTERVAL seconds
    driven by ratchet advance — same schedule as key rotation
    """

    ROTATION_INTERVAL = 5.0  # seconds

    def __init__(self):
        self._current_seed = os.urandom(32)
        self._encode_map: Dict[int, str] = {}
        self._decode_map: Dict[str, int] = {}
        self._map_timestamp = 0.0
        self._lock = threading.Lock()
        self._rotation_count = 0
        self._active_packs: List[str] = []
        self._rotate_map()

    def _derive_map_seed(self, base_seed: bytes) -> bytes:
        """Derive substitution map seed from ratchet seed."""
        return fast_hash(base_seed + b"CTW-polyglot-map-v1")

    def _rotate_map(self):
        """Rotate substitution map using fresh entropy."""
        # Mix current seed with physical entropy
        physical = os.urandom(32)
        new_seed = fast_hash(self._current_seed + physical +
                             struct.pack("Q", time.monotonic_ns()))
        self._current_seed = new_seed

        map_seed = self._derive_map_seed(new_seed)
        gen = SubstitutionMapGenerator(map_seed)
        encode, decode = gen.generate()

        with self._lock:
            self._encode_map = encode
            self._decode_map = decode
            self._map_timestamp = time.monotonic()
            self._rotation_count += 1
            self._active_packs = gen.pack_names_used()

        print(f"[CTW-POLYGLOT] Map rotated | "
              f"Rotation #{self._rotation_count} | "
              f"Packs: {', '.join(self._active_packs[:3])}...")

    def _check_rotation(self):
        """Rotate map if interval elapsed."""
        if time.monotonic() - self._map_timestamp > self.ROTATION_INTERVAL:
            self._rotate_map()

    def substitute_encode(self, data: bytes) -> str:
        """Apply unicode substitution to bytes."""
        self._check_rotation()
        with self._lock:
            return "".join(self._encode_map[b] for b in data)

    def substitute_decode(self, text: str) -> bytes:
        """Reverse unicode substitution to bytes."""
        with self._lock:
            result = []
            for char in text:
                if char in self._decode_map:
                    result.append(self._decode_map[char])
                else:
                    raise ValueError(f"Unknown character in ciphertext: "
                                     f"U+{ord(char):04X} — map may have rotated")
            return bytes(result)

    def encrypt_full(self, plaintext: bytes,
                     aes_key: bytes) -> dict:
        """
        Full two-layer encryption.
        Layer 1: AES-GCM-SIV
        Layer 2: Unicode substitution of ciphertext bytes
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

        # Layer 1: AES-GCM-SIV
        nonce = os.urandom(12)
        aesgcmsiv = AESGCMSIV(aes_key)
        aes_ciphertext = aesgcmsiv.encrypt(nonce, plaintext, None)

        # Layer 2: Unicode substitution of AES output
        self._check_rotation()
        unicode_ciphertext = self.substitute_encode(aes_ciphertext)

        return {
            "version": "CTW-polyglot-v1",
            "rotation": self._rotation_count,
            "nonce": nonce.hex(),
            "ciphertext": unicode_ciphertext,
            "pack_hint": self._active_packs[0]  # First pack as hint only
        }

    def decrypt_full(self, packet: dict, aes_key: bytes) -> bytes:
        """
        Full two-layer decryption.
        Must use same map state as encryption — keys must be synchronized.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

        nonce = bytes.fromhex(packet["nonce"])
        unicode_ct = packet["ciphertext"]

        # Layer 2 reverse: unicode → bytes
        aes_ciphertext = self.substitute_decode(unicode_ct)

        # Layer 1 reverse: AES-GCM-SIV decrypt
        aesgcmsiv = AESGCMSIV(aes_key)
        return aesgcmsiv.decrypt(nonce, aes_ciphertext, None)

    def status(self) -> dict:
        return {
            "rotation_count": self._rotation_count,
            "active_packs": self._active_packs,
            "map_age_seconds": round(time.monotonic() - self._map_timestamp, 2),
            "next_rotation_in": round(
                self.ROTATION_INTERVAL - (time.monotonic() - self._map_timestamp), 2
            )
        }


###############################################################################
# AUTO-ROTATION DAEMON
###############################################################################

class PolyglotRotationDaemon(threading.Thread):
    """Forces map rotation on schedule independent of encrypt/decrypt calls."""

    def __init__(self, cipher: CTWPolyglotCipher):
        super().__init__(daemon=True)
        self.cipher = cipher
        self._stop = threading.Event()

    def run(self):
        print("[CTW-DAEMON] Polyglot rotation daemon started")
        while not self._stop.is_set():
            time.sleep(self.cipher.ROTATION_INTERVAL +
                       (int.from_bytes(os.urandom(2), 'big') / 65535) * 2.0)
            self.cipher._rotate_map()

    def stop(self):
        self._stop.set()


###############################################################################
# DEMO
###############################################################################

if __name__ == "__main__":
    print("=" * 60)
    print(" CTW Polyglot Cipher Layer v1.0")
    print(" Unicode polyalphabet + AES-GCM-SIV")
    print("=" * 60)

    cipher = CTWPolyglotCipher()
    daemon = PolyglotRotationDaemon(cipher)
    daemon.start()

    # Demo key — in production this comes from CTWPhysicalRatchet.advance()
    demo_key = os.urandom(32)
    plaintext = b"CTW forensic payload — multilingual obfuscation layer active"

    print(f"\n[*] Plaintext: {plaintext.decode()}")
    print(f"\n[*] Status: {json.dumps(cipher.status(), indent=2)}")

    packet = cipher.encrypt_full(plaintext, demo_key)
    print(f"\n[*] Encrypted packet:")
    print(f"    Nonce: {packet['nonce']}")
    print(f"    Pack hint: {packet['pack_hint']}")
    print(f"    Ciphertext preview: {packet['ciphertext'][:80]}")
    print(f"    [looks like multilingual noise to pattern matchers]")

    recovered = cipher.decrypt_full(packet, demo_key)
    print(f"\n[*] Decrypted: {recovered.decode()}")

    print(f"\n[*] Waiting for rotation...")
    time.sleep(6)
    print(f"\n[*] Status after rotation: {json.dumps(cipher.status(), indent=2)}")

    print("\n[CTW] CTRL+C to stop")
    try:
        while True:
            time.sleep(5)
            print(f"[*] {json.dumps(cipher.status(), indent=2)}")
    except KeyboardInterrupt:
        daemon.stop()
        print("\n[CTW] Polyglot cipher daemon stopped.")

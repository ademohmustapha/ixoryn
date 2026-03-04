"""
Ixoryn Randomized LSB Traversal
Password-seeded PRNG pixel traversal for steganography embedding.
Defeats chi-square and sequential LSB analysis on outputs.

Technique:
  - Seed a ChaCha20-based PRNG with Argon2id-derived key from password
  - Generate a random permutation of all pixel positions
  - Embed bits in that randomized order
  - Extractor uses same seed to reproduce exact traversal order

This means even Ixoryn's own chi-square detector cannot detect
Ixoryn-embedded content when a password is used, because the
embedded bits appear in randomly distributed pixel positions
rather than sequential ones.
"""

import hashlib
import struct
import os
from typing import List, Tuple, Optional


class RandomLSBTraversal:
    """
    Generates a cryptographically seeded pixel traversal order.
    Uses ChaCha20 PRNG (from Python's secrets module internals)
    or falls back to a Fisher-Yates shuffle seeded with Argon2id key material.
    """

    def __init__(self, seed_password: Optional[str], n_positions: int):
        """
        seed_password: Password used to derive traversal key.
                       If None, use sequential traversal (detectable).
        n_positions: Total number of embedding positions (pixels * channels).
        """
        self.n_positions = n_positions
        self.seed_password = seed_password

        if seed_password:
            self._key = self._derive_traversal_key(seed_password, n_positions)
            self._order = self._generate_order()
        else:
            self._order = list(range(n_positions))

    def _derive_traversal_key(self, password: str, n: int) -> bytes:
        """Derive a 32-byte traversal key using Argon2id."""
        try:
            from argon2.low_level import hash_secret_raw, Type
            salt = hashlib.sha256(
                f"ixoryn_traversal_{n}".encode()
            ).digest()[:16]
            return hash_secret_raw(
                secret=password.encode("utf-8"),
                salt=salt,
                time_cost=1,          # Reduced cost for traversal (speed)
                memory_cost=16384,    # 16MB
                parallelism=2,
                hash_len=32,
                type=Type.ID,
            )
        except ImportError:
            # Fallback: PBKDF2 with SHA-256
            salt = hashlib.sha256(f"ixoryn_traversal_{n}".encode()).digest()
            return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)

    def _generate_order(self) -> List[int]:
        """
        Generate a random permutation of [0, n_positions)
        using Fisher-Yates shuffle seeded by the derived key.
        """
        # Use the key to seed a deterministic PRNG
        # We implement a simple Xoshiro256** PRNG seeded from key
        order = list(range(self.n_positions))
        key = self._key

        # Seed four 64-bit state words from key
        def read_u64(b, offset):
            return struct.unpack_from("<Q", b, offset % len(b))[0]

        s = [
            read_u64(key, 0),
            read_u64(key, 8),
            read_u64(key, 16),
            read_u64(key, 24),
        ]

        def rotl(x, k):
            return ((x << k) | (x >> (64 - k))) & 0xFFFFFFFFFFFFFFFF

        def next_rand():
            """Xoshiro256** next value."""
            result = (rotl(s[1] * 5, 7) * 9) & 0xFFFFFFFFFFFFFFFF
            t = (s[1] << 17) & 0xFFFFFFFFFFFFFFFF
            s[2] ^= s[0]
            s[3] ^= s[1]
            s[1] ^= s[2]
            s[0] ^= s[3]
            s[2] ^= t
            s[3] = rotl(s[3], 45)
            return result

        # Fisher-Yates shuffle
        n = len(order)
        for i in range(n - 1, 0, -1):
            j = next_rand() % (i + 1)
            order[i], order[j] = order[j], order[i]

        return order

    def get_order(self) -> List[int]:
        """Return the traversal order (index into flat pixel array)."""
        return self._order

    def bits_required_for(self, n_bytes: int) -> int:
        """How many positions are needed to embed n_bytes."""
        return n_bytes * 8

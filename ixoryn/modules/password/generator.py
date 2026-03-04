"""
Ixoryn Password Generator
Generates cryptographically secure passwords using secrets module.
"""

import secrets
import string
import re
from typing import Optional


class PasswordGenerator:
    LOWER = string.ascii_lowercase
    UPPER = string.ascii_uppercase
    DIGITS = string.digits
    SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    WORD_LIST = [
        "apple", "brave", "cloud", "dance", "eagle", "flame", "grant", "honey",
        "ivory", "jumbo", "karma", "lunar", "maple", "noble", "ocean", "pixel",
        "quiet", "river", "solar", "tiger", "ultra", "vivid", "witch", "xenon",
        "yield", "zebra", "amber", "blaze", "coral", "delta", "ember", "frost",
        "grace", "heron", "indigo", "jazz", "knight", "lotus", "magic", "north",
        "onyx", "prime", "quest", "raven", "storm", "torch", "unity", "valor",
        "whisky", "xray", "yarrow", "zephyr", "atomic", "binary", "cipher",
        "dragon", "enigma", "falcon", "galaxy", "hammer", "iris", "jaguar",
        "nebula", "orbit", "plasma", "quasar", "rocket", "saturn", "tundra",
        "umbra", "vertex", "walrus", "xenith", "yperite", "zenith",
    ]

    def generate(self, length: int = 20, strength: str = "high") -> str:
        """Generate a cryptographically secure password."""
        if length < 8:
            length = 8
        if length > 128:
            length = 128

        if strength == "medium":
            charset = self.LOWER + self.UPPER + self.DIGITS
            required = [
                secrets.choice(self.LOWER),
                secrets.choice(self.UPPER),
                secrets.choice(self.DIGITS),
            ]
        elif strength == "passphrase":
            return self._generate_passphrase(word_count=5)
        else:  # high
            charset = self.LOWER + self.UPPER + self.DIGITS + self.SPECIAL
            required = [
                secrets.choice(self.LOWER),
                secrets.choice(self.UPPER),
                secrets.choice(self.DIGITS),
                secrets.choice(self.SPECIAL),
            ]

        remaining = [secrets.choice(charset) for _ in range(length - len(required))]
        password_chars = required + remaining

        # Shuffle using cryptographically secure shuffle
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        return "".join(password_chars)

    def _generate_passphrase(self, word_count: int = 5) -> str:
        """Generate a Diceware-style passphrase."""
        words = [secrets.choice(self.WORD_LIST) for _ in range(word_count)]
        separator = secrets.choice(["-", "_", ".", "#"])
        # Capitalize one random word and add a number
        idx = secrets.randbelow(word_count)
        words[idx] = words[idx].capitalize()
        suffix = str(secrets.randbelow(9999)).zfill(4)
        return separator.join(words) + separator + suffix

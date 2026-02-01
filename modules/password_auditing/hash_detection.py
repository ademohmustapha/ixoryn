import re

HASH_PATTERNS = {
    "MD5": r"^[a-f0-9]{32}$",
    "SHA1": r"^[a-f0-9]{40}$",
    "SHA256": r"^[a-f0-9]{64}$",
    "SHA512": r"^[a-f0-9]{128}$",
    "bcrypt": r"^\$2[aby]\$.{56}$",
    "argon2": r"^\$argon2"
}

def detect_hash_type(hash_value: str):
    for name, pattern in HASH_PATTERNS.items():
        if re.match(pattern, hash_value.lower()):
            return name
    return "Unknown"


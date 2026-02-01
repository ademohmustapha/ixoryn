from modules.password_auditing.entropy import calculate_entropy
from modules.password_auditing.cracking_time import estimate_crack_time
from modules.password_auditing.strength import classify_strength
from modules.password_auditing.hash_detection import detect_hash_type

def audit_password(password: str):
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    strength = classify_strength(entropy)

    return {
        "entropy_bits": entropy,
        "strength": strength,
        "crack_time": crack_time,
        "length": len(password)
    }

def audit_hash(hash_value: str):
    hash_type = detect_hash_type(hash_value)

    strength_map = {
        "MD5": "Broken",
        "SHA1": "Broken",
        "SHA256": "Strong",
        "SHA512": "Very Strong",
        "bcrypt": "Very Strong",
        "argon2": "Excellent"
    }

    return {
        "hash_type": hash_type,
        "hash_strength": strength_map.get(hash_type, "Unknown")
    }


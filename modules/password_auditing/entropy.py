import math

CHARSETS = {
    "lower": 26,
    "upper": 26,
    "digits": 10,
    "symbols": 32
}

def calculate_entropy(password: str) -> float:
    charset_size = 0

    if any(c.islower() for c in password):
        charset_size += CHARSETS["lower"]
    if any(c.isupper() for c in password):
        charset_size += CHARSETS["upper"]
    if any(c.isdigit() for c in password):
        charset_size += CHARSETS["digits"]
    if any(not c.isalnum() for c in password):
        charset_size += CHARSETS["symbols"]

    if charset_size == 0:
        return 0.0

    entropy = math.log2(charset_size ** len(password))
    return round(entropy, 2)


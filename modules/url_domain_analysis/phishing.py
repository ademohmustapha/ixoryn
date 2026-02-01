import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update",
    "account", "bank", "confirm", "signin"
]

def detect_phishing(url):
    score = 0
    parsed = urlparse(url)

    if parsed.scheme not in ["https"]:
        score += 1

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url.lower():
            score += 1

    if re.search(r"\d{1,3}(\.\d{1,3}){3}", parsed.netloc):
        score += 2

    return {
        "phishing_score": score,
        "risk": "High" if score >= 3 else "Low"
    }


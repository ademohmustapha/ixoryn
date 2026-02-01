import tldextract
import difflib

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "amazon.com",
    "apple.com", "microsoft.com", "paypal.com"
]

def detect_typosquatting(domain):
    extracted = tldextract.extract(domain)
    base = f"{extracted.domain}.{extracted.suffix}"

    matches = []
    for legit in POPULAR_DOMAINS:
        ratio = difflib.SequenceMatcher(None, base, legit).ratio()
        if ratio > 0.8 and base != legit:
            matches.append(legit)

    return {
        "possible_typosquatting": bool(matches),
        "similar_to": matches
    }


import idna

def detect_homograph(domain):
    try:
        ascii_domain = idna.encode(domain).decode()
        if ascii_domain != domain:
            return {
                "homograph_detected": True,
                "punycode": ascii_domain
            }
    except Exception:
        pass

    return {
        "homograph_detected": False
    }


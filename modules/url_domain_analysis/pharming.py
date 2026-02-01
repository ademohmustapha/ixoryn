import dns.resolver

def detect_pharming(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [r.to_text() for r in answers]

        suspicious = any(ip.startswith("192.") or ip.startswith("10.") for ip in ips)

        return {
            "resolved_ips": ips,
            "pharming_suspected": suspicious
        }

    except Exception as e:
        return {
            "error": str(e),
            "pharming_suspected": True
        }


from urllib.parse import urlparse
from modules.url_domain_analysis.phishing import detect_phishing
from modules.url_domain_analysis.typosquatting import detect_typosquatting
from modules.url_domain_analysis.homograph import detect_homograph
from modules.url_domain_analysis.pharming import detect_pharming

def analyze_domain(input_value):
    if not input_value.startswith("http"):
        url = "http://" + input_value
    else:
        url = input_value

    parsed = urlparse(url)
    domain = parsed.netloc

    results = {
        "domain": domain
    }

    results.update(detect_phishing(url))
    results.update(detect_typosquatting(domain))
    results.update(detect_homograph(domain))
    results.update(detect_pharming(domain))

    return results


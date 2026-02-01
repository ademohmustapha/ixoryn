def classify_strength(entropy_bits: float):
    if entropy_bits < 40:
        return "Very Weak"
    elif entropy_bits < 60:
        return "Weak"
    elif entropy_bits < 80:
        return "Moderate"
    elif entropy_bits < 100:
        return "Strong"
    else:
        return "Very Strong"


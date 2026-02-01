def estimate_crack_time(entropy_bits: float):
    # Conservative estimates
    online_rate = 100          # guesses/sec
    offline_rate = 1e10        # GPU guesses/sec

    online_seconds = (2 ** entropy_bits) / online_rate
    offline_seconds = (2 ** entropy_bits) / offline_rate

    return {
        "online": seconds_to_readable(online_seconds),
        "offline": seconds_to_readable(offline_seconds)
    }

def seconds_to_readable(seconds):
    units = [
        ("years", 31536000),
        ("days", 86400),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1)
    ]

    for name, unit in units:
        if seconds >= unit:
            value = seconds / unit
            return f"{value:.2f} {name}"

    return "instantly"


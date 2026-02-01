import os
import random
from modules.steganography.stego_detector import analyze_stego

def random_bytes(size=1024):
    return os.urandom(size)

def fuzz_stego(iterations=100):
    for i in range(iterations):
        filename = f"fuzz_{i}.bin"
        with open(filename, "wb") as f:
            f.write(random_bytes(random.randint(10, 5000)))

        try:
            analyze_stego(filename)
        except Exception:
            print(f"[!] Crash detected on {filename}")
        finally:
            os.remove(filename)

if __name__ == "__main__":
    fuzz_stego()


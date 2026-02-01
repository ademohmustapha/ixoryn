import os
import random
from modules.crypto.crypto import encrypt_file

def fuzz_crypto(iterations=50):
    for i in range(iterations):
        filename = f"crypto_fuzz_{i}.txt"
        with open(filename, "w") as f:
            f.write(os.urandom(100).hex())

        try:
            encrypt_file(filename, "weakpass")
        except Exception:
            print(f"[!] Crypto error on {filename}")
        finally:
            os.remove(filename)

if __name__ == "__main__":
    fuzz_crypto()


import subprocess
import sys

REQUIRED = [
    "cryptography",
    "argon2-cffi",
    "rich",
    "python-magic",
    "pillow",
    "opencv-python",
    "soundfile",
    "pydub",
    "passlib",
    "dnspython",
    "idna",
    "tldextract",
    "numpy"
]

def is_installed(pkg):
    try:
        __import__(pkg.replace("-", "_"))
        return True
    except ImportError:
        return False

def bootstrap():
    missing = [p for p in REQUIRED if not is_installed(p)]

    if not missing:
        return True

    print("[!] Missing dependencies:")
    for m in missing:
        print(f"   - {m}")

    choice = input("Install now? (Y/n): ").strip().lower()
    if choice == "n":
        print("[-] Cannot proceed without dependencies.")
        sys.exit(1)

    for pkg in missing:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

    print("[+] All dependencies installed.")
    return True


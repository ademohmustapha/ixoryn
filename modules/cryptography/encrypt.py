import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from modules.cryptography.key_management import derive_key, generate_salt
from modules.password_auditing.auditor import audit_password
from core.file_picker import pick_file

def encrypt_file():
    file_path = pick_file("Select file to encrypt")
    if not file_path:
        return

    password = input("Create encryption password: ")

    audit = audit_password(password)
    if audit["entropy_bits"] < 60:
        print("[-] Password too weak. Encryption aborted.")
        return

    salt = generate_salt()
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    with open(file_path, "rb") as f:
        data = f.read()

    ciphertext = aesgcm.encrypt(nonce, data, None)

    output = file_path + ".ixoryn"
    with open(output, "wb") as f:
        f.write(salt + nonce + ciphertext)

    print(f"[+] File encrypted successfully: {output}")
    print(f"[!] Save this salt securely: {salt.hex()}")


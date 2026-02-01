from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from modules.cryptography.key_management import derive_key
from core.file_picker import pick_file

def decrypt_file():
    file_path = pick_file("Select encrypted file")
    if not file_path:
        return

    password = input("Enter password: ")
    salt_hex = input("Enter salt (hex): ")

    salt = bytes.fromhex(salt_hex)

    with open(file_path, "rb") as f:
        data = f.read()

    nonce = data[16:28]
    ciphertext = data[28:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        print("[-] Decryption failed. Wrong password or corrupted file.")
        return

    output = file_path.replace(".ixoryn", ".decrypted")
    with open(output, "wb") as f:
        f.write(plaintext)

    print(f"[+] File decrypted successfully: {output}")


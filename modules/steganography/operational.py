from core.file_picker import pick_file
from modules.steganography.lossless_converter import (
    convert_image_to_png,
    convert_audio_to_wav
)
from modules.steganography.image_stego import embed_data
from modules.steganography.audio_stego import embed_audio
from modules.password_auditing.auditor import audit_password
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def operational_mode():
    cover = pick_file("Select cover image or audio")
    payload_path = pick_file("Select file to hide")

    if not cover or not payload_path:
        return

    password = input("Create stego password: ")
    audit = audit_password(password)
    if audit["entropy_bits"] < 60:
        print("[-] Weak password. Aborting.")
        return

    with open(payload_path, "rb") as f:
        payload = f.read()

    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = nonce + aes.encrypt(nonce, payload, None)

    if cover.lower().endswith((".png", ".jpg", ".jpeg")):
        lossless = convert_image_to_png(cover)
        embed_data(lossless, encrypted, "stego_output.png")

    elif cover.lower().endswith((".wav", ".mp3", ".flac")):
        lossless = convert_audio_to_wav(cover)
        embed_audio(lossless, encrypted, "stego_output.wav")

    print("[+] Steganography completed successfully.")


from core.file_picker import pick_file
from modules.steganography.lossless_converter import *
from modules.steganography.image_stego import *
from modules.steganography.audio_stego import *
from modules.steganography.stego_detector import analyze_stego

def research_mode():
    stego = pick_file("Select suspected stego file")
    if not stego:
        return

    print("[*] Running forensic steganalysis...")
    result = analyze_stego(stego)

    for k, v in result.items():
        print(f"{k}: {v}")


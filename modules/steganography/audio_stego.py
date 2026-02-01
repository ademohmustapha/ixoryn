import soundfile as sf
import numpy as np

def embed_audio(audio_path, payload: bytes, output_path):
    data, rate = sf.read(audio_path, dtype='int16')
    flat = data.flatten()

    payload += b"###END###"
    bits = ''.join(format(b, '08b') for b in payload)

    if len(bits) > len(flat):
        raise ValueError("Payload too large for audio.")

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & ~1) | int(bit)

    stego = flat.reshape(data.shape)
    sf.write(output_path, stego, rate, format="WAV")

def extract_audio(audio_path):
    data, _ = sf.read(audio_path, dtype='int16')
    flat = data.flatten()

    bits = ''.join(str(sample & 1) for sample in flat)

    payload = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        payload.append(int(byte, 2))
        if payload[-8:] == b"###END###":
            return bytes(payload[:-8])

    return None


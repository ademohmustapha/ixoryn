from PIL import Image

def embed_data(image_path, payload: bytes, output_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    payload += b"###END###"
    bits = ''.join(format(b, '08b') for b in payload)

    if len(bits) > len(pixels) * 3:
        raise ValueError("Payload too large for image.")

    new_pixels = []
    bit_idx = 0

    for pixel in pixels:
        r, g, b = pixel
        if bit_idx < len(bits):
            r = (r & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | int(bits[bit_idx])
            bit_idx += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_path, format="PNG")

def extract_data(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())

    bits = ""
    for r, g, b in pixels:
        bits += str(r & 1)
        bits += str(g & 1)
        bits += str(b & 1)

    data = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        data.append(int(byte, 2))
        if data[-8:] == b"###END###":
            return bytes(data[:-8])

    return None


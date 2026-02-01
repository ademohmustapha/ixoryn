import numpy as np
from PIL import Image

def analyze_stego(path):
    results = {}

    if path.lower().endswith(".png"):
        img = Image.open(path)
        pixels = np.array(img)
        lsb_plane = pixels & 1
        variance = np.var(lsb_plane)

        results["type"] = "Image"
        results["lsb_variance"] = round(float(variance), 6)
        results["suspicion"] = "High" if variance > 0.25 else "Low"

    elif path.lower().endswith(".wav"):
        results["type"] = "Audio"
        results["analysis"] = "LSB audio analysis placeholder"
        results["suspicion"] = "Medium"

    else:
        results["error"] = "Unsupported format"

    return results


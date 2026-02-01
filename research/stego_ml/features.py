import numpy as np
from PIL import Image

def extract_image_features(image_path):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    lsb = pixels & 1

    features = [
        np.mean(lsb),
        np.var(lsb),
        np.std(lsb),
        np.mean(np.abs(np.diff(lsb.flatten()))),
    ]

    return np.array(features)


import os
import numpy as np
from features import extract_image_features

def load_dataset(clean_dir, stego_dir):
    X, y = [], []

    for f in os.listdir(clean_dir):
        X.append(extract_image_features(os.path.join(clean_dir, f)))
        y.append(0)

    for f in os.listdir(stego_dir):
        X.append(extract_image_features(os.path.join(stego_dir, f)))
        y.append(1)

    return np.array(X), np.array(y)


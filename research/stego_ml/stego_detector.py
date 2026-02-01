import numpy as np
import joblib
from PIL import Image
from research.stego_ml.features import extract_image_features

MODEL_PATH = "research/stego_ml/model.pkl"

def analyze_stego(path):
    results = {}

    try:
        model = joblib.load(MODEL_PATH)
        features = extract_image_features(path).reshape(1, -1)
        prob = model.predict_proba(features)[0][1]

        results["ml_stego_probability"] = round(float(prob), 4)
        results["ml_verdict"] = "Stego detected" if prob > 0.7 else "Likely clean"

    except Exception as e:
        results["ml_error"] = str(e)

    return results


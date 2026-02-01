from sklearn.linear_model import LogisticRegression
import joblib
from dataset import load_dataset

X, y = load_dataset("data/clean", "data/stego")

model = LogisticRegression()
model.fit(X, y)

joblib.dump(model, "model.pkl")
print("[+] ML stego model trained and saved.")


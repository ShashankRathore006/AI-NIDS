import pandas as pd
import joblib

MODEL_FILE = "models/nids_random_forest.pkl"
DATASET_FILE = "datasets/processed/nids_5class.csv"

print("=" * 60)
print("NIDS MODEL TEST")
print("=" * 60)

# Load model
model = joblib.load(MODEL_FILE)

print("\nModel loaded successfully.")

# Load data
df = pd.read_csv(DATASET_FILE)

X = df.drop(columns=["AttackType"])
y = df["AttackType"]

# Test first 10 samples
predictions = model.predict(X.head(10))

print("\nPredictions:")
print("-" * 60)

for i, (actual, predicted) in enumerate(
    zip(y.head(10), predictions),
    start=1
):
    result = "PASS" if actual == predicted else "WRONG"

    print(
        f"{i:2}. "
        f"Actual: {actual:15} "
        f"Predicted: {predicted:15} "
        f"[{result}]"
    )

print("\nTest complete.")

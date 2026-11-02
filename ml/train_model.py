import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

DATASET_FILE = Path("datasets/processed/nids_5class.csv")
MODEL_DIR = Path("models")
MODEL_FILE = MODEL_DIR / "nids_random_forest.pkl"

print("=" * 70)
print("AI-NIDS MODEL TRAINING")
print("=" * 70)

# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATASET_FILE)

print(f"Dataset shape: {df.shape}")

# ------------------------------------------------------------
# FEATURES / LABEL
# ------------------------------------------------------------

X = df.drop(columns=["AttackType"])
y = df["AttackType"]

print(f"Features: {X.shape[1]}")
print(f"Samples: {X.shape[0]}")

# ------------------------------------------------------------
# TRAIN / TEST
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"\nTraining samples: {len(X_train):,}")
print(f"Testing samples:  {len(X_test):,}")

# ------------------------------------------------------------
# RANDOM FOREST
# ------------------------------------------------------------

print("\nCreating Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=4
)

# ------------------------------------------------------------
# TRAIN
# ------------------------------------------------------------

print("Training model...")

model.fit(X_train, y_train)

print("Training complete!")

# ------------------------------------------------------------
# TEST
# ------------------------------------------------------------

print("\nTesting model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n" + "=" * 70)
print("MODEL PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        y_pred,
        digits=4
    )
)

# ------------------------------------------------------------
# CONFUSION MATRIX
# ------------------------------------------------------------

labels = [
    "BENIGN",
    "DoS",
    "DDoS",
    "Port Scan",
    "Brute Force"
]

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=labels
)

print("\nConfusion Matrix:")
print()

print(
    f"{'':15}"
    + "".join(
        f"{label[:10]:>12}"
        for label in labels
    )
)

for label, row in zip(labels, cm):

    print(
        f"{label:15}"
        + "".join(
            f"{value:12}"
            for value in row
        )
    )

# ------------------------------------------------------------
# FEATURE IMPORTANCE
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TOP FEATURES")
print("=" * 70)

importance = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(
    ascending=False
)

for feature, value in importance.items():

    print(
        f"{feature:35} {value:.4f}"
    )

# ------------------------------------------------------------
# SAVE MODEL
# ------------------------------------------------------------

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_FILE
)

print("\n" + "=" * 70)
print(f"MODEL SAVED: {MODEL_FILE}")
print("=" * 70)

import pandas as pd
from pathlib import Path

DATASET_DIR = Path("datasets/raw")

csv_files = list(DATASET_DIR.rglob("*.csv"))

if not csv_files:
    print("ERROR: No CSV files found.")
    exit()

total_labels = {}

print("=" * 70)
print("COUNTING ALL DATASET LABELS")
print("=" * 70)

for file in csv_files:

    print(f"\nReading: {file.name}")

    try:
        # Only load the Label column.
        # This saves a lot of RAM.
        df = pd.read_csv(
            file,
            usecols=lambda column: column.strip() == "Label"
        )

        df.columns = df.columns.str.strip()

        counts = df["Label"].value_counts()

        print("\nLabels in this file:")

        for label, count in counts.items():
            print(f"  {label:35} {count:,}")

            total_labels[label] = (
                total_labels.get(label, 0) + count
            )

    except Exception as e:
        print(f"ERROR: {e}")

print("\n" + "=" * 70)
print("TOTAL LABEL DISTRIBUTION")
print("=" * 70)

total_samples = 0

for label, count in sorted(
    total_labels.items(),
    key=lambda x: x[1],
    reverse=True
):

    print(f"{label:35} {count:,}")
    total_samples += count

print("\n" + "-" * 70)
print(f"TOTAL SAMPLES: {total_samples:,}")
print("-" * 70)

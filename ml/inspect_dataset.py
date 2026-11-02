import pandas as pd
from pathlib import Path

DATASET_DIR = Path("datasets/raw")

# Search for CSV files inside all subfolders
csv_files = list(DATASET_DIR.rglob("*.csv"))

if not csv_files:
    print("ERROR: No CSV files found.")
    exit()

print("=" * 70)
print("CICIDS2017 DATASET INSPECTION")
print("=" * 70)

print(f"\nFound {len(csv_files)} CSV files:\n")

for file in csv_files:
    print(f"  {file}")

# Inspect every CSV
for file in csv_files:

    print("\n" + "=" * 70)
    print(f"FILE: {file.name}")
    print("=" * 70)

    try:
        # Only read 1000 rows initially
        df = pd.read_csv(file, nrows=1000)

        # Remove spaces from column names
        df.columns = df.columns.str.strip()

        print(f"Rows inspected: {len(df):,}")
        print(f"Columns: {len(df.columns)}")

        print("\nFirst 10 columns:")

        for column in df.columns[:10]:
            print(f"  - {column}")

        print("\nLabel distribution in inspected rows:")

        if "Label" in df.columns:
            print(df["Label"].value_counts())
        else:
            print("WARNING: Label column not found.")

        print("\nMissing values:")

        missing = df.isnull().sum()
        missing = missing[missing > 0]

        if len(missing) == 0:
            print("  No missing values in inspected rows.")
        else:
            print(missing)

    except Exception as e:
        print(f"ERROR reading {file}: {e}")




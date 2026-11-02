import pandas as pd
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================

RAW_DIR = Path("datasets/raw")
OUTPUT_DIR = Path("datasets/processed")
OUTPUT_FILE = OUTPUT_DIR / "nids_5class.csv"

SAMPLES_PER_CLASS = 13_000
RANDOM_STATE = 42
CHUNK_SIZE = 100_000


# ============================================================
# FEATURES
# ============================================================

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "Average Packet Size"
]


# ============================================================
# LABEL MAPPING
# ============================================================

def map_label(label):

    label = str(label).strip()

    if label == "BENIGN":
        return "BENIGN"

    if label.startswith("DoS"):
        return "DoS"

    if label == "DDoS":
        return "DDoS"

    if label == "PortScan":
        return "Port Scan"

    if label in ["FTP-Patator", "SSH-Patator"]:
        return "Brute Force"

    return None


# ============================================================
# FIND CSV FILES
# ============================================================

csv_files = list(RAW_DIR.rglob("*.csv"))

if not csv_files:
    print("ERROR: No CSV files found.")
    exit()


print("=" * 70)
print("NIDS DATASET PREPARATION")
print("=" * 70)

print(f"\nFound {len(csv_files)} CSV files.")


# ============================================================
# STORE DATA BY CLASS
# ============================================================

class_data = {
    "BENIGN": [],
    "DoS": [],
    "DDoS": [],
    "Port Scan": [],
    "Brute Force": []
}


# ============================================================
# PROCESS FILES
# ============================================================

for file in csv_files:

    print("\n" + "-" * 70)
    print(f"Reading: {file.name}")
    print("-" * 70)

    try:

        # ----------------------------------------------------
        # STEP 1: Read only the header
        # ----------------------------------------------------

        header = pd.read_csv(
            file,
            nrows=0,
            encoding="utf-8",
            encoding_errors="replace"
        )

        # Original column names
        original_columns = list(header.columns)

        # Cleaned column names
        cleaned_columns = [
            str(column).strip()
            for column in original_columns
        ]

        # Map cleaned name -> original name
        column_map = dict(
            zip(cleaned_columns, original_columns)
        )

        # Check required columns
        required_columns = FEATURES + ["Label"]

        missing = [
            column
            for column in required_columns
            if column not in column_map
        ]

        if missing:

            print("WARNING: Missing columns:")

            for column in missing:
                print(f"  - {column}")

            continue

        # Actual column names used by pandas
        columns_to_read = [
            column_map[column]
            for column in required_columns
        ]

        # ----------------------------------------------------
        # STEP 2: Read CSV in chunks
        # ----------------------------------------------------

        chunks = pd.read_csv(
            file,
            usecols=columns_to_read,
            chunksize=CHUNK_SIZE,
            encoding="utf-8",
            encoding_errors="replace"
        )

        for chunk in chunks:

            # Clean column names
            chunk.columns = chunk.columns.str.strip()

            # ------------------------------------------------
            # Map attack labels
            # ------------------------------------------------

            chunk["AttackType"] = (
                chunk["Label"]
                .apply(map_label)
            )

            # Remove unwanted attacks
            chunk = chunk[
                chunk["AttackType"].notna()
            ].copy()

            if chunk.empty:
                continue

            # ------------------------------------------------
            # Keep only our features
            # ------------------------------------------------

            chunk = chunk[
                FEATURES + ["AttackType"]
            ]

            # ------------------------------------------------
            # Convert values to numeric
            # ------------------------------------------------

            for feature in FEATURES:

                chunk[feature] = pd.to_numeric(
                    chunk[feature],
                    errors="coerce"
                )

            # ------------------------------------------------
            # Remove infinity
            # ------------------------------------------------

            chunk = chunk.replace(
                [float("inf"), float("-inf")],
                pd.NA
            )

            # ------------------------------------------------
            # Remove missing values
            # ------------------------------------------------

            chunk = chunk.dropna()

            if chunk.empty:
                continue

            # ------------------------------------------------
            # Store rows by class
            # ------------------------------------------------

            for attack_type in class_data:

                subset = chunk[
                    chunk["AttackType"] == attack_type
                ]

                if len(subset) == 0:
                    continue

                class_data[attack_type].append(
                    subset
                )

        print("File processed successfully.")

    except Exception as e:

        print(
            f"ERROR processing {file.name}:"
        )

        print(e)


# ============================================================
# COMBINE AND BALANCE
# ============================================================

print("\n" + "=" * 70)
print("COMBINING AND BALANCING CLASSES")
print("=" * 70)

final_data = []


for attack_type, dataframes in class_data.items():

    if not dataframes:

        print(
            f"\nERROR: No data found for "
            f"{attack_type}"
        )

        continue

    combined = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        f"\n{attack_type}: "
        f"{len(combined):,} available"
    )

    # Don't take more than we have
    sample_size = min(
        SAMPLES_PER_CLASS,
        len(combined)
    )

    sampled = combined.sample(
        n=sample_size,
        random_state=RANDOM_STATE
    )

    final_data.append(sampled)

    print(
        f"Using: {len(sampled):,}"
    )


# ============================================================
# SAFETY CHECK
# ============================================================

if not final_data:

    print("\nERROR: No usable data was found.")

    print(
        "Check the errors above."
    )

    exit()


# ============================================================
# CREATE FINAL DATASET
# ============================================================

final_df = pd.concat(
    final_data,
    ignore_index=True
)


# Shuffle
final_df = final_df.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(drop=True)


# ============================================================
# SAVE
# ============================================================

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

final_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# FINAL REPORT
# ============================================================

print("\n" + "=" * 70)
print("FINAL DATASET")
print("=" * 70)

print(
    f"\nOutput file:\n{OUTPUT_FILE}"
)

print(
    f"\nTotal rows: "
    f"{len(final_df):,}"
)

print(
    f"\nNumber of features: "
    f"{len(FEATURES)}"
)

print("\nFeatures:")

for feature in FEATURES:
    print(f"  - {feature}")

print("\nClass distribution:")

print(
    final_df["AttackType"]
    .value_counts()
)

print("\nDataset preparation COMPLETE.")

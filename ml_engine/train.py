"""
train.py -- Train UpgradedAMIDES on combined SOCBED + NSL-KDD data.

Steps:
  1. Load SOCBED data from ml_engine/model/ (synthetic samples per category)
  2. Load NSL-KDD from data/KDDTrain+.csv
     -> If not found locally, auto-download via kagglehub (pip install kagglehub)
  3. Combine both datasets
  4. Train UpgradedAMIDES on the combined data
  5. Save model to ml_engine/upgraded_amides.pkl

Usage:
  python ml_engine/train.py
  (run from the project root directory)
"""

import sys
import shutil
from pathlib import Path
from collections import Counter

# Add project root to sys.path so ml_engine is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine.upgraded_amides import UpgradedAMIDES

# -- Paths (relative to project root) -----------------------------------------
SOCBED_DIR  = PROJECT_ROOT / 'ml_engine' / 'model'
NSLKDD_PATH = PROJECT_ROOT / 'data' / 'KDDTrain+.csv'
OUTPUT_PATH = PROJECT_ROOT / 'ml_engine' / 'upgraded_amides.pkl'

# kagglehub dataset slug for NSL-KDD
KAGGLE_DATASET = "hassan06/nslkdd"

# Candidate filenames to look for inside the downloaded kagglehub folder
# (the dataset ships as .txt files that are CSV-formatted)
_NSLKDD_CANDIDATES = [
    "KDDTrain+.txt",
    "KDDTrain+.csv",
    "KDDTrain+_20Percent.txt",
    "NSL-KDD Train.csv",
]


def print_section(title: str):
    print(f"\n{'-' * 60}")
    print(f"  {title}")
    print(f"{'-' * 60}")


def _find_nslkdd_in_dir(directory: Path) -> Path | None:
    """
    Recursively search *directory* for a known NSL-KDD training file.
    Returns the first match, or None if nothing found.
    """
    for candidate in _NSLKDD_CANDIDATES:
        matches = list(directory.rglob(candidate))
        if matches:
            return matches[0]
    return None


def _download_nslkdd() -> Path | None:
    """
    Download NSL-KDD via kagglehub and return the path to the training CSV.

    Requires:
      pip install kagglehub
      Kaggle API credentials in ~/.kaggle/kaggle.json  (or KAGGLE_* env vars)

    Returns the resolved path to the training file, or None on failure.
    """
    try:
        import kagglehub  # type: ignore[import-untyped]  # optional dependency
    except ImportError:
        print("  [INFO] kagglehub not installed. Skipping auto-download.")
        print("         To enable: pip install kagglehub")
        return None

    print(f"  Downloading NSL-KDD from Kaggle ({KAGGLE_DATASET}) ...")
    try:
        dl_path = kagglehub.dataset_download(KAGGLE_DATASET)
        print(f"  Downloaded to: {dl_path}")
    except Exception as exc:
        print(f"  [WARN] kagglehub download failed: {exc}")
        print("         Ensure ~/.kaggle/kaggle.json exists with valid credentials.")
        return None

    found = _find_nslkdd_in_dir(Path(dl_path))
    if found is None:
        print(f"  [WARN] Could not locate a KDDTrain file inside {dl_path}")
        print(f"         Expected one of: {_NSLKDD_CANDIDATES}")
        return None

    # Copy the file to data/KDDTrain+.csv so future runs skip the download
    NSLKDD_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(found, NSLKDD_PATH)
    print(f"  Saved to project: {NSLKDD_PATH}")
    return NSLKDD_PATH


def main():
    model = UpgradedAMIDES()
    all_lines:  list = []
    all_labels: list = []

    # -- Step 1: SOCBED data ---------------------------------------------------
    print_section("Step 1 -- Loading SOCBED data")
    print(f"  Directory: {SOCBED_DIR}")

    if SOCBED_DIR.exists():
        lines, labels = model.train_from_socbed(str(SOCBED_DIR))
        all_lines.extend(lines)
        all_labels.extend(labels)
        print(f"  -> {len(lines)} SOCBED samples loaded")
    else:
        print(f"  [WARN] SOCBED directory not found at {SOCBED_DIR}")
        print("         Continuing without SOCBED data.")

    # -- Step 2: NSL-KDD data --------------------------------------------------
    print_section("Step 2 -- Loading NSL-KDD data")

    nslkdd_file = NSLKDD_PATH
    if not nslkdd_file.exists():
        print(f"  KDDTrain+.csv not found at {NSLKDD_PATH}")
        print("  Attempting auto-download via kagglehub ...")
        nslkdd_file = _download_nslkdd()

    if nslkdd_file and nslkdd_file.exists():
        print(f"  File: {nslkdd_file}")
        lines, labels = model.train_from_csv(str(nslkdd_file))
        all_lines.extend(lines)
        all_labels.extend(labels)
        print(f"  -> {len(lines)} NSL-KDD samples loaded")
    else:
        print("  [WARN] NSL-KDD data unavailable. Options:")
        print("    A) pip install kagglehub  then add ~/.kaggle/kaggle.json")
        print("    B) Download manually: https://www.kaggle.com/datasets/hassan06/nslkdd")
        print("       Place KDDTrain+.txt at: data/KDDTrain+.csv")
        print("  Continuing without NSL-KDD data.")

    # -- Step 3: Validate combined dataset ------------------------------------
    print_section("Step 3 -- Combined dataset summary")

    if not all_lines:
        print("  [ERROR] No training data available.")
        print("  Provide at least one of:")
        print("    - ml_engine/model/ (SOCBED folders)")
        print("    - data/KDDTrain+.csv (NSL-KDD)")
        sys.exit(1)

    dist = Counter(all_labels)
    print(f"  Total samples : {len(all_lines)}")
    print(f"  {'Class':<20} {'Count':>8}  {'%':>6}")
    print(f"  {'-'*38}")
    for cls in sorted(dist):
        pct = dist[cls] / len(all_labels) * 100
        print(f"  {cls:<20} {dist[cls]:>8}  {pct:>5.1f}%")

    # -- Step 4: Train ---------------------------------------------------------
    print_section("Step 4 -- Training UpgradedAMIDES")
    model.train(all_lines, all_labels)

    # -- Step 5: Save ----------------------------------------------------------
    print_section("Step 5 -- Saving model")
    model.save(str(OUTPUT_PATH))

    print(f"\n{'='*60}")
    print("  Training complete!")
    print(f"  Model saved to: {OUTPUT_PATH}")
    print(f"  Run test:       python ml_engine/test.py")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()

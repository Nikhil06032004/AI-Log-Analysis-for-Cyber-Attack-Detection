"""
data.py — Download and prepare NSL-KDD dataset files for UpgradedAMIDES.

Downloads KDDTrain+.txt and KDDTest+.txt from Kaggle via kagglehub
and saves them to data/ as KDDTrain+.csv and KDDTest+.csv.

Usage:
  python data/data.py           # download everything
  python data/data.py --status  # check what's already present

Requirements:
  pip install kagglehub
  Kaggle API key at ~/.kaggle/kaggle.json
  (get it from: https://www.kaggle.com/settings ->API ->Create New Token)
"""

import sys
import shutil
import argparse
from pathlib import Path

DATA_DIR       = Path(__file__).resolve().parent
KAGGLE_DATASET = "hassan06/nslkdd"

# Source filename inside the Kaggle download ->destination in data/
FILES = {
    "KDDTrain+.txt":            "KDDTrain+.csv",
    "KDDTest+.txt":             "KDDTest+.csv",
    "KDDTrain+_20Percent.txt":  "KDDTrain+_20Percent.csv",  # optional small subset
}


def _count_rows(path: Path) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except Exception:
        return -1


def status():
    """Print which data files are already present."""
    print("\nNSL-KDD data file status:")
    print(f"  {'File':<30} {'Rows':>10}  Present")
    print(f"  {'-'*50}")
    for _, dst_name in FILES.items():
        dst = DATA_DIR / dst_name
        if dst.exists():
            rows = _count_rows(dst)
            print(f"  {dst_name:<30} {rows:>10,}  [OK]")
        else:
            print(f"  {dst_name:<30} {'--':>10}   [MISSING]")
    print()


def download():
    """Download NSL-KDD via kagglehub and copy files to data/."""
    try:
        import kagglehub  # type: ignore[import-untyped]
    except ImportError:
        print("[ERROR] kagglehub is not installed.")
        print("  Run: pip install kagglehub")
        sys.exit(1)

    print(f"Downloading NSL-KDD dataset ({KAGGLE_DATASET}) from Kaggle …")
    print("(Already-cached downloads are instant)\n")

    try:
        dl_path = Path(kagglehub.dataset_download(KAGGLE_DATASET))
    except Exception as exc:
        print(f"[ERROR] Download failed: {exc}")
        print("  Ensure ~/.kaggle/kaggle.json contains valid API credentials.")
        print("  Get your key at: https://www.kaggle.com/settings ->API")
        sys.exit(1)

    print(f"Source directory: {dl_path}\n")
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    any_copied = False
    for src_name, dst_name in FILES.items():
        dst = DATA_DIR / dst_name

        # Find the source file anywhere inside the download tree
        matches = list(dl_path.rglob(src_name))
        if not matches:
            print(f"  [SKIP] {src_name} not found in download — skipping")
            continue

        src = matches[0]  # take the first (non-nested) match
        shutil.copy2(src, dst)
        rows = _count_rows(dst)
        size_mb = dst.stat().st_size / 1_048_576
        print(f"  [OK] {src_name:<30} -> data/{dst_name:<28}  {rows:>8,} rows  ({size_mb:.1f} MB)")
        any_copied = True

    if any_copied:
        print(f"\nAll files saved to: {DATA_DIR}")
        print("\nNext steps:")
        print("  Train the model  -> python ml_engine/train.py")
        print("  Evaluate model   -> python ml_engine/test.py")
    else:
        print("\n[WARN] No files were copied.")


def main():
    parser = argparse.ArgumentParser(description="NSL-KDD data downloader")
    parser.add_argument(
        "--status", action="store_true",
        help="Show which data files are already present (no download)",
    )
    args = parser.parse_args()

    if args.status:
        status()
    else:
        status()       # show current state before download
        download()
        status()       # show updated state after download


if __name__ == "__main__":
    main()

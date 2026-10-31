#!/usr/bin/env python3

import csv
import sys
from pathlib import Path


def safe_rate(numerator, denominator):
    if denominator == 0:
        return 0.0
    return numerator / denominator


def main():
    csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs/test_results.csv")

    if not csv_path.exists():
        print(f"CSV file not found: {csv_path}")
        return 1

    tp = tn = fp = fn = 0

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sample_type = row.get("type", "").strip().lower()
            actual_status = row.get("actual_status", "").strip()
            blocked = actual_status == "403"

            if sample_type == "attack":
                if blocked:
                    tp += 1
                else:
                    fn += 1
            elif sample_type == "normal":
                if blocked:
                    fp += 1
                else:
                    tn += 1

    total = tp + tn + fp + fn
    detection_rate = safe_rate(tp, tp + fn)
    false_positive_rate = safe_rate(fp, fp + tn)
    accuracy = safe_rate(tp + tn, total)

    print("LiteWAF-NGX Metric Report")
    print(f"Input CSV: {csv_path}")
    print()
    print(f"TP: {tp}")
    print(f"TN: {tn}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")
    print()
    print(f"detection_rate: {detection_rate:.2%}")
    print(f"false_positive_rate: {false_positive_rate:.2%}")
    print(f"accuracy: {accuracy:.2%}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

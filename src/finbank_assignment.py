"""Deterministic FinBank vulnerability assignment layer.

Assigns the existing TraceWard vulnerability records to FinBank systems
without modifying the original dataset. The assignment is deterministic,
explainable, and biases distribution toward more critical systems.
"""

from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

from src.finbank_env import _default_finbank_systems
from src.utils import write_text_atomic

RAW_VULNERABILITIES_PATH = Path("data/raw/vulnerabilities.csv")
OUTPUT_INVENTORY_PATH = Path("artifacts/finbank/finbank_vulnerability_inventory.csv")

FIXED_SEED = 42

SYSTEM_WEIGHTS = [
    ("INTERNET", 1),
    ("WEB01", 4),
    ("APP01", 4),
    ("AUTH01", 5),
    ("VPN01", 4),
    ("EMP01", 2),
    ("DB01", 5),
    ("BACKUP01", 5),
]


def _build_weighted_assignment(total_records: int = 1200, seed: int = FIXED_SEED) -> list[str]:
    total_weight = sum(weight for _, weight in SYSTEM_WEIGHTS)
    if total_weight <= 0:
        raise ValueError("Total system weight must be positive.")
    base_per_weight = total_records / total_weight

    assignments: list[str] = []
    for system_id, weight in SYSTEM_WEIGHTS:
        count = int(round(weight * base_per_weight))
        assignments.extend([system_id] * count)

    # Correct rounding drift by adding/removing from the highest-weighted system
    drift = total_records - len(assignments)
    if drift > 0:
        assignments.extend([max(SYSTEM_WEIGHTS, key=lambda x: x[1])[0]] * drift)
    elif drift < 0:
        remove_system = max(SYSTEM_WEIGHTS, key=lambda x: x[1])[0]
        for _ in range(-drift):
            assignments.remove(remove_system)

    rng = random.Random(seed)
    rng.shuffle(assignments)
    return assignments


def assign_finbank_vulnerabilities(
    input_path: str | Path = RAW_VULNERABILITIES_PATH,
    output_path: str | Path = OUTPUT_INVENTORY_PATH,
    seed: int = FIXED_SEED,
) -> pd.DataFrame:
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(f"Raw vulnerabilities file not found: {input_path}")

    df = pd.read_csv(input_path, keep_default_na=False)
    if len(df) != 1200:
        raise ValueError(f"Expected 1200 vulnerability records, got {len(df)}.")

    assignments = _build_weighted_assignment(total_records=len(df), seed=seed)
    if len(assignments) != len(df):
        raise ValueError("Assignment list length does not match vulnerability count.")

    df = df.copy()
    df["system_id"] = assignments

    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(output_path, df.to_csv(index=False, lineterminator="\n"))
    return df


def get_finbank_assignment_summary(df: pd.DataFrame) -> pd.DataFrame:
    summary = (
        df.groupby("system_id")
        .size()
        .reset_index(name="vulnerability_count")
        .sort_values(by=["vulnerability_count", "system_id"], ascending=[False, True])
        .reset_index(drop=True)
    )
    return summary


if __name__ == "__main__":
    result_df = assign_finbank_vulnerabilities()
    summary = get_finbank_assignment_summary(result_df)
    print(f"Assigned {len(result_df)} vulnerabilities to FinBank systems.")
    print(summary.to_string(index=False))
    print(f"\nSaved inventory to: {OUTPUT_INVENTORY_PATH}")

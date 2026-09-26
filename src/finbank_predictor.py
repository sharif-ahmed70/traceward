"""FinBank operational predictor.

Generates full-inventory risk predictions from the existing trained TraceWard
KNN model. This module is separate from evaluation and does not alter the
held-out test metrics or existing KNN algorithm.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd

from src.knn_classifier import FEATURE_COLUMNS, load_trained_model, predict_single_vulnerability

FINBANK_PROCESSED_DATA_PATH = Path("data/processed/vulnerabilities_processed.csv")
KNN_MODEL_PATH = Path("artifacts/knn/knn_model.joblib")
OUTPUT_PREDICTIONS_PATH = Path("artifacts/finbank/finbank_predictions.csv")


def _load_processed_data(path: str | Path = FINBANK_PROCESSED_DATA_PATH) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Processed vulnerability data not found: {p}")
    df = pd.read_csv(p, keep_default_na=False)
    required = FEATURE_COLUMNS + ["vuln_id", "system_id", "risk_label"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Processed data missing required columns: {missing}")
    return df


def _load_model(model_path: str | Path = KNN_MODEL_PATH):
    p = Path(model_path)
    if not p.exists():
        raise FileNotFoundError(f"KNN model artifact not found at {p}")
    return load_trained_model(p)


def predict_full_inventory(
    processed_data_path: str | Path = FINBANK_PROCESSED_DATA_PATH,
    model_path: str | Path = KNN_MODEL_PATH,
    output_path: str | Path = OUTPUT_PREDICTIONS_PATH,
) -> pd.DataFrame:
    """Predict risk labels for all vulnerabilities in the processed dataset.

    Uses the existing trained TraceWard KNN pipeline. The held-out test set
    is not touched; this function operates on the full inventory only.

    Args:
        processed_data_path: Path to the full processed vulnerability dataset.
        model_path: Path to the trained KNN pipeline artifact.
        output_path: Destination CSV path for operational predictions.

    Returns:
        DataFrame with columns: vuln_id, system_id, actual_risk, predicted_risk
    """
    processed = _load_processed_data(processed_data_path)
    model = _load_model(model_path)

    records = []
    for _, row in processed.iterrows():
        features = {col: float(row[col]) for col in FEATURE_COLUMNS}
        prediction = predict_single_vulnerability(features, model=model)
        records.append({
            "vuln_id": str(row["vuln_id"]),
            "system_id": str(row["system_id"]),
            "actual_risk": str(row["risk_label"]),
            "predicted_risk": prediction["predicted_risk"],
        })

    df = pd.DataFrame(records, columns=["vuln_id", "system_id", "actual_risk", "predicted_risk"])

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False, encoding="utf-8", lineterminator="\n")
    return df


def load_finbank_predictions(path: str | Path = OUTPUT_PREDICTIONS_PATH) -> pd.DataFrame:
    """Load the FinBank operational predictions artifact."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"FinBank predictions artifact not found: {p}")
    df = pd.read_csv(p, keep_default_na=False)
    required = {"vuln_id", "system_id", "actual_risk", "predicted_risk"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"FinBank predictions missing required columns: {sorted(missing)}")
    return df


if __name__ == "__main__":
    results = predict_full_inventory()
    print(f"Generated {len(results)} operational predictions.")
    print(results.head())
    print(f"\nSaved to: {OUTPUT_PREDICTIONS_PATH}")

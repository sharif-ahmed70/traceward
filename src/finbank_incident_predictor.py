"""FinBank incident risk predictor.

Uses the existing trained TraceWard KNN pipeline to predict risk for
vulnerabilities associated with a FinBank incident. The KNN algorithm,
model artifact, and preprocessing are not modified.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd

from src.knn_classifier import FEATURE_COLUMNS, load_trained_model, predict_single_vulnerability

FINBANK_PROCESSED_DATA_PATH = Path("data/processed/vulnerabilities_processed.csv")
KNN_MODEL_PATH = Path("artifacts/knn/knn_model.joblib")


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


def predict_incident_risks(
    vuln_ids: list[str],
    processed_data_path: str | Path = FINBANK_PROCESSED_DATA_PATH,
    model_path: str | Path = KNN_MODEL_PATH,
) -> pd.DataFrame:
    """Predict KNN risk labels for vulnerabilities associated with an incident.

    Args:
        vuln_ids: List of vulnerability IDs to predict.
        processed_data_path: Path to the processed vulnerability dataset.
        model_path: Path to the trained KNN pipeline artifact.

    Returns:
        DataFrame with columns: vuln_id, system_id, predicted_risk, risk_label
    """
    processed = _load_processed_data(processed_data_path)
    model = _load_model(model_path)

    records = []
    for vuln_id in vuln_ids:
        row = processed.loc[processed["vuln_id"] == vuln_id]
        if row.empty:
            raise KeyError(f"Vulnerability ID not found in processed data: '{vuln_id}'")
        record = row.iloc[0]
        features = {col: float(record[col]) for col in FEATURE_COLUMNS}
        prediction = predict_single_vulnerability(features, model=model)
        records.append({
            "vuln_id": str(record["vuln_id"]),
            "system_id": str(record["system_id"]),
            "predicted_risk": prediction["predicted_risk"],
            "risk_label": str(record["risk_label"]),
        })

    return pd.DataFrame(records, columns=["vuln_id", "system_id", "predicted_risk", "risk_label"])


def predict_incident_risks_from_inventory(
    incident_related_vulnerabilities: list[str],
    inventory: Optional[pd.DataFrame] = None,
    inventory_path: str | Path = "artifacts/finbank/finbank_vulnerability_inventory.csv",
    processed_data_path: str | Path = FINBANK_PROCESSED_DATA_PATH,
    model_path: str | Path = KNN_MODEL_PATH,
) -> pd.DataFrame:
    """Predict KNN risk for vulnerabilities using the FinBank inventory.

    This function maps incident-related vulnerability IDs to their processed
    features and predicts risk using the existing trained KNN pipeline.
    System identifiers are taken from the FinBank inventory.

    Args:
        incident_related_vulnerabilities: Vulnerability IDs from an incident.
        inventory: Optional FinBank vulnerability inventory DataFrame.
        inventory_path: Path to the FinBank vulnerability inventory.
        processed_data_path: Path to the processed vulnerability dataset.
        model_path: Path to the trained KNN pipeline artifact.

    Returns:
        DataFrame with columns: vuln_id, system_id, predicted_risk, risk_label
    """
    if inventory is None:
        p = Path(inventory_path)
        if not p.exists():
            raise FileNotFoundError(f"FinBank vulnerability inventory not found: {p}")
        inventory = pd.read_csv(p, keep_default_na=False)

    valid_vuln_ids = set(inventory["vuln_id"].tolist())
    invalid = [v for v in incident_related_vulnerabilities if v not in valid_vuln_ids]
    if invalid:
        raise ValueError(f"Vulnerability IDs not in FinBank inventory: {invalid}")

    processed = _load_processed_data(processed_data_path)
    model = _load_model(model_path)
    inventory_by_vuln = inventory.set_index("vuln_id")["system_id"].to_dict()

    records = []
    for vuln_id in incident_related_vulnerabilities:
        proc_row = processed.loc[processed["vuln_id"] == vuln_id]
        if proc_row.empty:
            raise KeyError(f"Vulnerability ID not found in processed data: '{vuln_id}'")
        record = proc_row.iloc[0]
        features = {col: float(record[col]) for col in FEATURE_COLUMNS}
        prediction = predict_single_vulnerability(features, model=model)
        records.append({
            "vuln_id": str(vuln_id),
            "system_id": str(inventory_by_vuln.get(vuln_id, record["system_id"])),
            "predicted_risk": prediction["predicted_risk"],
            "risk_label": str(record["risk_label"]),
        })

    return pd.DataFrame(records, columns=["vuln_id", "system_id", "predicted_risk", "risk_label"])


if __name__ == "__main__":
    test_vuln_ids = ["V0001", "V0002", "V0003"]
    results = predict_incident_risks(test_vuln_ids)
    print(results.to_string(index=False))

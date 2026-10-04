"""Risk engine providing system-level risk aggregation from vulnerability predictions."""

from pathlib import Path
import pandas as pd
from src.utils import write_text_atomic

RISK_SCORE_MAP = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

SCORE_TO_RISK_MAP = {
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}

REQUIRED_PREDICTION_COLUMNS = [
    "vuln_id",
    "system_id",
    "predicted_risk",
]

SUMMARY_COLUMNS = [
    "system_id",
    "vulnerability_count",
    "highest_risk",
    "average_risk_score",
    "normalized_risk",
    "critical_count",
    "high_or_critical_count",
]


def risk_label_to_score(label):
    """Convert a risk label string to an integer score from 1 to 4."""
    if not isinstance(label, str) or label not in RISK_SCORE_MAP:
        raise ValueError(
            f"Invalid risk label '{label}'. Allowed labels are: Low, Medium, High, Critical."
        )
    return RISK_SCORE_MAP[label]


def validate_predictions(df):
    """Validate that vulnerability prediction DataFrame has required columns and valid values."""
    if not isinstance(df, pd.DataFrame):
        raise ValueError("Input must be a pandas DataFrame.")

    missing_cols = [c for c in REQUIRED_PREDICTION_COLUMNS if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required prediction columns: {missing_cols}")

    if (df["vuln_id"].astype(str).str.strip() == "").any() or df["vuln_id"].isnull().any():
        raise ValueError("vuln_id contains empty or null values.")

    if (df["system_id"].astype(str).str.strip() == "").any() or df["system_id"].isnull().any():
        raise ValueError("system_id contains empty or null values.")

    invalid_labels = set(df["predicted_risk"]) - set(RISK_SCORE_MAP.keys())
    if invalid_labels:
        raise ValueError(
            f"Invalid predicted_risk values: {invalid_labels}. Allowed labels: Low, Medium, High, Critical."
        )

    return True


def add_numeric_risk(df):
    """Add a risk_score column (1-4) to a copy of the predictions DataFrame."""
    validate_predictions(df)
    df_copy = df.copy()
    df_copy["risk_score"] = df_copy["predicted_risk"].map(RISK_SCORE_MAP)
    return df_copy


def summarize_system_risk(df):
    """
    Aggregate vulnerability-level predictions into a system-level risk summary DataFrame.

    Columns produced:
    system_id, vulnerability_count, highest_risk, average_risk_score,
    normalized_risk, critical_count, high_or_critical_count.
    """
    validate_predictions(df)
    scored = add_numeric_risk(df)

    records = []
    for system_id, group in scored.groupby("system_id"):
        count = len(group)
        max_score = int(group["risk_score"].max())
        highest_risk = SCORE_TO_RISK_MAP[max_score]
        avg_score = round(float(group["risk_score"].mean()), 3)
        normalized_risk = round(avg_score / 4.0, 3)
        critical_count = int((group["predicted_risk"] == "Critical").sum())
        high_or_critical_count = int(group["predicted_risk"].isin(["High", "Critical"]).sum())

        records.append({
            "system_id": system_id,
            "vulnerability_count": count,
            "highest_risk": highest_risk,
            "average_risk_score": avg_score,
            "normalized_risk": normalized_risk,
            "critical_count": critical_count,
            "high_or_critical_count": high_or_critical_count,
        })

    summary_df = pd.DataFrame(records, columns=SUMMARY_COLUMNS)

    # Sort by normalized_risk descending, then system_id ascending
    summary_df = summary_df.sort_values(
        by=["normalized_risk", "system_id"],
        ascending=[False, True],
    ).reset_index(drop=True)

    return summary_df


def build_system_risk_summary(
    input_path="artifacts/knn/predictions.csv",
    output_path="artifacts/risk/system_risk_summary.csv",
    predictions_path=None,
):
    """Read a predictions CSV, compute system risk summary, and save to CSV without index.

    If predictions_path is provided, it takes precedence over input_path.
    """
    if predictions_path is not None:
        input_path = predictions_path

    df = pd.read_csv(input_path, keep_default_na=False)
    summary_df = summarize_system_risk(df)

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(out_path, summary_df.to_csv(index=False))

    return summary_df


URGENCY_LEVELS = (
    (60, "Urgent", "within 24 hours"),
    (45, "High", "within 3 days"),
    (30, "Medium", "within 2 weeks"),
    (0, "Low", "in the next maintenance cycle"),
)


def contextual_priority(predicted_risk, system, on_attack_path=False, is_chokepoint=False):
    """Combine a vulnerability's predicted risk class with where it sits in the network.

    The KNN risk class depends only on CVSS features, so it is identical on every host.
    How urgent the fix is depends on the host: its business criticality (1-5), internet
    exposure, and whether it lies on the A* attack path or is a chokepoint.

    Args:
        predicted_risk: "Low" | "Medium" | "High" | "Critical"
        system: network node dict with "criticality" and "internet_exposed"

    Returns:
        dict with score, level, fix_within and plain-language reasons.
    """
    criticality = int(system.get("criticality", 3))
    exposed = bool(system.get("internet_exposed", False))
    parts = [
        (risk_label_to_score(predicted_risk) * 10, f"the weakness itself is rated {predicted_risk}"),
        (criticality * 4, f"this server's business importance is {criticality} out of 5"),
    ]
    if exposed:
        parts.append((8, "it can be reached directly from the internet"))
    if on_attack_path:
        parts.append((10, "it lies on the easiest attack route to the Database Server"))
    if is_chokepoint:
        parts.append((6, "every attack route passes through it"))

    score = sum(points for points, _ in parts)
    for threshold, level, fix_within in URGENCY_LEVELS:
        if score >= threshold:
            break
    return {
        "score": score,
        "level": level,
        "fix_within": fix_within,
        "reasons": [reason for _, reason in parts],
    }

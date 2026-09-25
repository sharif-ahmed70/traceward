"""Functions for preparing and cleaning vulnerability data before it is used by the learning modules."""

from pathlib import Path
import pandas as pd

# Mappings for categorical features
ATTACK_COMPLEXITY_MAP = {
    "Low": 0,
    "High": 1,
}

PRIVILEGES_REQUIRED_MAP = {
    "None": 0,
    "Low": 1,
    "High": 2,
}

USER_INTERACTION_MAP = {
    "None": 0,
    "Required": 1,
}

CONFIDENTIALITY_IMPACT_MAP = {
    "None": 0,
    "Low": 1,
    "High": 2,
}

INTEGRITY_IMPACT_MAP = {
    "None": 0,
    "Low": 1,
    "High": 2,
}

AVAILABILITY_IMPACT_MAP = {
    "None": 0,
    "Low": 1,
    "High": 2,
}

REQUIRED_COLUMNS = [
    "vuln_id",
    "system_id",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploit_probability",
    "risk_label",
    "description",
]

ALLOWED_RISK_LABELS = {
    "Low",
    "Medium",
    "High",
    "Critical",
}

PROCESSED_COLUMNS = [
    "vuln_id",
    "system_id",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploit_probability",
    "risk_label",
]


def load_raw_data(path="data/raw/vulnerabilities.csv"):
    """Load raw vulnerability CSV without treating 'None' as missing value."""
    return pd.read_csv(path, encoding="utf-8", keep_default_na=False)


def validate_raw_data(df):
    """Validate that raw vulnerability dataframe satisfies all schema rules and constraints."""
    # 1. Required columns
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")

    # 2. No empty cells or missing values
    if (df == "").any().any() or df.isnull().any().any():
        raise ValueError("Dataset contains empty cells or missing values.")

    # 3. Unique vuln_id
    if not df["vuln_id"].is_unique:
        raise ValueError("Duplicate vuln_id values found in dataset.")

    # 4. Categorical column allowed values
    invalid_ac = set(df["attack_complexity"]) - set(ATTACK_COMPLEXITY_MAP.keys())
    if invalid_ac:
        raise ValueError(f"Invalid attack_complexity values: {invalid_ac}")

    invalid_pr = set(df["privileges_required"]) - set(PRIVILEGES_REQUIRED_MAP.keys())
    if invalid_pr:
        raise ValueError(f"Invalid privileges_required values: {invalid_pr}")

    invalid_ui = set(df["user_interaction"]) - set(USER_INTERACTION_MAP.keys())
    if invalid_ui:
        raise ValueError(f"Invalid user_interaction values: {invalid_ui}")

    invalid_ci = set(df["confidentiality_impact"]) - set(CONFIDENTIALITY_IMPACT_MAP.keys())
    if invalid_ci:
        raise ValueError(f"Invalid confidentiality_impact values: {invalid_ci}")

    invalid_ii = set(df["integrity_impact"]) - set(INTEGRITY_IMPACT_MAP.keys())
    if invalid_ii:
        raise ValueError(f"Invalid integrity_impact values: {invalid_ii}")

    invalid_ai = set(df["availability_impact"]) - set(AVAILABILITY_IMPACT_MAP.keys())
    if invalid_ai:
        raise ValueError(f"Invalid availability_impact values: {invalid_ai}")

    # 5. Risk label
    invalid_risks = set(df["risk_label"]) - ALLOWED_RISK_LABELS
    if invalid_risks:
        raise ValueError(f"Invalid risk_label values: {invalid_risks}")

    # 6. exploit_probability numeric and in range [0.0, 1.0]
    try:
        probs = pd.to_numeric(df["exploit_probability"])
    except Exception as e:
        raise ValueError(f"exploit_probability contains non-numeric values: {e}") from e

    if (probs < 0.0).any() or (probs > 1.0).any():
        raise ValueError("exploit_probability values must be between 0.0 and 1.0.")

    return True


def encode_features(df):
    """Encode categorical security attributes into numerical values and exclude display fields."""
    encoded = df.copy()

    encoded["attack_complexity"] = encoded["attack_complexity"].map(ATTACK_COMPLEXITY_MAP)
    encoded["privileges_required"] = encoded["privileges_required"].map(PRIVILEGES_REQUIRED_MAP)
    encoded["user_interaction"] = encoded["user_interaction"].map(USER_INTERACTION_MAP)
    encoded["confidentiality_impact"] = encoded["confidentiality_impact"].map(CONFIDENTIALITY_IMPACT_MAP)
    encoded["integrity_impact"] = encoded["integrity_impact"].map(INTEGRITY_IMPACT_MAP)
    encoded["availability_impact"] = encoded["availability_impact"].map(AVAILABILITY_IMPACT_MAP)
    encoded["exploit_probability"] = encoded["exploit_probability"].astype(float)

    return encoded[PROCESSED_COLUMNS]


def preprocess_vulnerabilities(
    input_path="data/raw/vulnerabilities.csv",
    output_path="data/processed/vulnerabilities_processed.csv",
):
    """Execute the complete preprocessing pipeline from raw CSV to processed CSV."""
    df = load_raw_data(input_path)
    validate_raw_data(df)
    processed_df = encode_features(df)

    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    processed_df.to_csv(output_path, index=False, encoding="utf-8", lineterminator="\n")
    return processed_df


if __name__ == "__main__":
    input_file = "data/raw/vulnerabilities.csv"
    output_file = "data/processed/vulnerabilities_processed.csv"
    processed_data = preprocess_vulnerabilities(input_file, output_file)
    print("Preprocessing completed successfully.")
    print(f"Processed {len(processed_data)} vulnerability records.")
    print(f"Saved to: {output_file}")

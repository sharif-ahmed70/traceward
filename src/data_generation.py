"""Generate reproducible synthetic vulnerability data for TraceWard."""

from pathlib import Path

import numpy as np
import pandas as pd


DEFAULT_OUTPUT_PATH = Path("data/raw/vulnerabilities.csv")
RANDOM_SEED = 42

TARGET_PER_CLASS = 300

RISK_LABELS = [
    "Low",
    "Medium",
    "High",
    "Critical",
]

SYSTEM_IDS = [
    "WEB01",
    "APP01",
    "AUTH01",
    "VPN01",
    "EMP01",
    "DB01",
    "BACKUP01",
]

ATTACK_COMPLEXITY = ["Low", "High"]
PRIVILEGES_REQUIRED = ["None", "Low", "High"]
USER_INTERACTION = ["None", "Required"]
IMPACT_LEVELS = ["None", "Low", "High"]


def calculate_hidden_risk_score(
    attack_complexity,
    privileges_required,
    user_interaction,
    confidentiality_impact,
    integrity_impact,
    availability_impact,
    exploit_probability,
):
    """
    Calculate a simple CVSS-inspired risk score.

    The score is used only to create the synthetic target label.
    It is never stored as a machine-learning feature.
    """

    impact_values = {
        "None": 0.0,
        "Low": 0.5,
        "High": 1.0,
    }

    complexity_values = {
        "Low": 1.0,
        "High": 0.45,
    }

    privilege_values = {
        "None": 1.0,
        "Low": 0.65,
        "High": 0.25,
    }

    interaction_values = {
        "None": 1.0,
        "Required": 0.55,
    }

    impact_score = (
        impact_values[confidentiality_impact]
        + impact_values[integrity_impact]
        + impact_values[availability_impact]
    ) / 3.0

    exploitability_score = (
        complexity_values[attack_complexity]
        + privilege_values[privileges_required]
        + interaction_values[user_interaction]
    ) / 3.0

    risk_score = 10 * (
        0.55 * impact_score
        + 0.30 * exploit_probability
        + 0.15 * exploitability_score
    )

    return round(risk_score, 3)


def score_to_label(score):
    """Convert the hidden synthetic risk score into a risk category."""

    if score < 3.5:
        return "Low"

    if score < 5.5:
        return "Medium"

    if score < 7.5:
        return "High"

    return "Critical"


def build_description(
    attack_complexity,
    confidentiality_impact,
    integrity_impact,
    availability_impact,
):
    """Create a short human-readable synthetic description."""

    impact_parts = []

    if confidentiality_impact == "High":
        impact_parts.append("data exposure")

    if integrity_impact == "High":
        impact_parts.append("data modification")

    if availability_impact == "High":
        impact_parts.append("service disruption")

    if not impact_parts:
        impact_text = "limited operational impact"
    else:
        impact_text = ", ".join(impact_parts)

    complexity_text = (
        "easy exploitation conditions"
        if attack_complexity == "Low"
        else "specific exploitation conditions"
    )

    return (
        f"Synthetic vulnerability with {complexity_text} "
        f"and possible {impact_text}."
    )


def generate_training_data(
    output_path=DEFAULT_OUTPUT_PATH,
    samples_per_class=TARGET_PER_CLASS,
    seed=RANDOM_SEED,
):
    """
    Generate a balanced synthetic vulnerability dataset.

    The hidden risk score is used only to assign labels.
    It is intentionally excluded from the saved dataset so that
    the ML models cannot directly learn from the answer itself.
    """

    rng = np.random.default_rng(seed)

    class_counts = {
        label: 0
        for label in RISK_LABELS
    }

    rows = []

    max_attempts = samples_per_class * len(RISK_LABELS) * 100
    attempts = 0

    while (
        any(
            count < samples_per_class
            for count in class_counts.values()
        )
        and attempts < max_attempts
    ):
        attempts += 1

        attack_complexity = rng.choice(
            ATTACK_COMPLEXITY
        )

        privileges_required = rng.choice(
            PRIVILEGES_REQUIRED
        )

        user_interaction = rng.choice(
            USER_INTERACTION
        )

        confidentiality_impact = rng.choice(
            IMPACT_LEVELS
        )

        integrity_impact = rng.choice(
            IMPACT_LEVELS
        )

        availability_impact = rng.choice(
            IMPACT_LEVELS
        )

        exploit_probability = round(
            float(rng.uniform(0.0, 1.0)),
            3,
        )

        hidden_score = calculate_hidden_risk_score(
            attack_complexity,
            privileges_required,
            user_interaction,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            exploit_probability,
        )

        risk_label = score_to_label(
            hidden_score
        )

        if class_counts[risk_label] >= samples_per_class:
            continue

        class_counts[risk_label] += 1

        rows.append(
            {
                "system_id": rng.choice(SYSTEM_IDS),
                "attack_complexity": attack_complexity,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
                "confidentiality_impact": confidentiality_impact,
                "integrity_impact": integrity_impact,
                "availability_impact": availability_impact,
                "exploit_probability": exploit_probability,
                "risk_label": risk_label,
                "description": build_description(
                    attack_complexity,
                    confidentiality_impact,
                    integrity_impact,
                    availability_impact,
                ),
            }
        )

    expected_total = (
        samples_per_class
        * len(RISK_LABELS)
    )

    if len(rows) != expected_total:
        raise RuntimeError(
            "Unable to generate the requested balanced dataset."
        )

    data = pd.DataFrame(rows)

    data.insert(
        0,
        "vuln_id",
        [
            f"V{i:04d}"
            for i in range(
                1,
                len(data) + 1,
            )
        ],
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data.to_csv(
        output_path,
        index=False,
        encoding="utf-8",
    )

    return data


if __name__ == "__main__":
    generated = generate_training_data()

    print("Synthetic training data generated successfully.")
    print(f"Total records: {len(generated)}")
    print(generated["risk_label"].value_counts().to_string())
    print("Saved to: data/raw/vulnerabilities.csv")

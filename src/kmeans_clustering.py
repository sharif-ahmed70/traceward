"""K-Means clustering to group similar vulnerability patterns."""
"""K-Means clustering module for TraceWard vulnerability structure analysis.

Groups vulnerabilities based on 7 encoded security characteristics.
Clusters represent structural vulnerability profiles, not severity ratings.
"""

from pathlib import Path
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploit_probability",
]


def run_kmeans(
    data_path="data/processed/vulnerabilities_processed.csv",
    output_path="artifacts/kmeans/cluster_assignments.csv",
    n_clusters=4,
    random_state=42,
):
    """Fit K-Means on the 7 security features and export cluster assignments.

    Output format:
    vuln_id, system_id, cluster_id
    """
    in_file = Path(data_path)
    if not in_file.exists():
        raise FileNotFoundError(f"Input data file not found: {data_path}")

    df = pd.read_csv(in_file)
    X = df[FEATURE_COLUMNS]

    # Standardize numeric features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Fit K-Means
    kmeans = KMeans(n_clusters=n_clusters, random_state=random_state, n_init=10)
    clusters = kmeans.fit_predict(X_scaled)

    assignments = pd.DataFrame({
        "vuln_id": df["vuln_id"],
        "system_id": df["system_id"],
        "cluster_id": clusters,
    })

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    assignments.to_csv(out_file, index=False)

    return assignments


if __name__ == "__main__":
    result = run_kmeans()
    print(f"K-Means clustering complete: {len(result)} records assigned to {result['cluster_id'].nunique()} clusters.")

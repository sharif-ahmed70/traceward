# TraceWard K-Means Cluster Analysis

## 1. Objective
K-Means clustering identifies structural vulnerability patterns across the dataset using the seven agreed security features. Clusters group vulnerabilities that are similar in their exploitability and impact characteristics, without using severity labels or identifiers.

## 2. Input
- **Processed dataset:** `data/processed/vulnerabilities_processed.csv`
- **Record count:** 1,200
- **Clustering features (7):**
  1. `attack_complexity`
  2. `privileges_required`
  3. `user_interaction`
  4. `confidentiality_impact`
  5. `integrity_impact`
  6. `availability_impact`
  7. `exploit_probability`

## 3. Method
- **Preprocessing dependency:** Input comes from the TraceWard preprocessing pipeline (`src/preprocessing.py`), which encodes categorical attributes into numeric values while preserving `vuln_id`, `system_id`, and `risk_label`.
- **Feature scaling:** `StandardScaler` from scikit-learn, fitted only on the input dataset being clustered. No external data is used during scaling.
- **K-Means implementation:** scikit-learn `KMeans` with `n_init=10` and fixed `random_state=42`.
- **K-selection approach:** Candidate K values evaluated from 2 through 8 using inertia and silhouette score. The final K is selected by the discrete centered second-difference elbow heuristic.
- **Reproducibility:** Fixed `random_state=42` ensures identical cluster assignments and metrics across repeated runs on the same input.

## 4. K Selection

| K  | Inertia  | Silhouette Score |
|----|----------|------------------|
| 2  | 6945.63  | 0.1648           |
| 3  | 6269.45  | 0.1465           |
| 4  | 5728.58  | 0.1488           |
| 5  | 5377.01  | 0.1503           |
| 6  | 5065.25  | 0.1640           |
| 7  | 4887.04  | 0.1488           |
| 8  | 4516.07  | 0.1781           |

- **Selected K:** 4
- **Deterministic selection rule:** Discrete centered second-difference elbow heuristic: C(k) = I(k-1) - 2·I(k) + I(k+1) evaluated over interior candidates k in [3, 7]. Maximum curvature occurs at K=4 (C(4) = 189.30), indicating the strongest elbow in inertia reduction.

## 5. Cluster Profiles

### Cluster 0 — 299 records (24.92%)
- **user_interaction:** None (mean = 0.0)
- **Impacts:** Low-to-moderate confidentiality (0.75), integrity (0.56), availability (0.58)
- **Exploit probability:** Lower (mean = 0.318)
- **Privileges required:** Mixed distribution (mean ≈ 1.01)

### Cluster 1 — 309 records (25.75%)
- **user_interaction:** Required (mean = 1.0)
- **Impacts:** Low across confidentiality (0.56), integrity (0.70), availability (0.56)
- **Exploit probability:** Lower (mean = 0.332)
- **Privileges required:** Mixed distribution (mean ≈ 1.05)

### Cluster 2 — 289 records (24.08%)
- **user_interaction:** None (mean = 0.0)
- **Impacts:** Elevated confidentiality (1.38), integrity (1.51), availability (1.57)
- **Exploit probability:** Higher (mean = 0.693)
- **Privileges required:** Lower requirements (mean ≈ 0.83)

### Cluster 3 — 303 records (25.25%)
- **user_interaction:** Required (mean = 1.0)
- **Impacts:** Elevated confidentiality (1.53), integrity (1.44), availability (1.44)
- **Exploit probability:** Highest (mean = 0.714)
- **Privileges required:** Lowest requirements (mean ≈ 0.78)

**Key structural separators:** `user_interaction` splits the clusters into two groups: Clusters 0 and 1 require no user interaction, while Clusters 2 and 3 require user interaction. Within each interaction group, impact severity and exploit probability further separate the clusters.

## 6. Risk-label Interpretation
`risk_label` was **not** used to create clusters. The `cluster_profiles.csv` includes risk-label distributions (`risk_low_count`, `risk_low_pct`, etc.) for **post-hoc human interpretation only**. These statistics describe which risk labels appear within each structural group but do not define cluster identity. Clusters should not be labeled as "Low", "Medium", "High", or "Critical" based solely on their post-hoc risk distributions.

## 7. Data Integrity
- **vuln_id preserved:** Yes, exact values maintained in `cluster_assignments.csv`
- **system_id preserved:** Yes, exact values maintained in `cluster_assignments.csv`
- **Seven features only:** Clustering uses only the seven agreed security features
- **No target leakage:** `risk_label` is excluded from clustering features
- **No ID leakage:** `vuln_id` and `system_id` are excluded from clustering features

## 8. Reproducibility
To regenerate all K-Means artifacts:
```bash
python -c "from src.kmeans_clustering import run_kmeans; run_kmeans()"
```
Or run the module directly:
```bash
python src/kmeans_clustering.py
```
Both commands produce identical results on the same input due to the fixed `random_state=42`.

## 9. Limitations
- **Synthetic dataset:** The current dataset is synthetically generated for development and pipeline validation. Real-world CVE/EPSS data may produce different cluster structures.
- **K-Means assumptions:** K-Means assumes spherical clusters of similar size and density. The modest silhouette scores (0.15–0.18) suggest overlapping or non-spherical structure in the feature space.
- **Ordinal encoding:** Categorical features are encoded as ordered integers (e.g., 0=None, 1=Low, 2=High). K-Means treats these as continuous distances, which may not perfectly reflect categorical semantics.
- **Structural similarity, not severity:** Clusters represent structural groupings across exploitability and impact dimensions. They are not direct severity classifications and should not be conflated with `risk_label` categories.

# TraceWard Module Contracts

This document specifies the responsibilities, inputs, and outputs for every module in TraceWard. It ensures that all five team members can work in parallel on their respective components with clear interface boundaries.

---

## Module Interfaces

### A. Preprocessing Module

- **File**: `src/preprocessing.py`
- **Responsibility**: Load raw vulnerability data and encode categorical attributes (such as attack complexity, privilege requirements, impacts) into machine-readable numeric formats suitable for machine learning algorithms.
- **Input**:
  - `data/raw/vulnerabilities.csv`
- **Expected Output**:
  - `data/processed/vulnerabilities_processed.csv`
- **Requirements**:
  - Encoded numerical features for model consumption.
  - Must preserve key identifier and label columns: `vuln_id`, `system_id`, and `risk_label`.

---

### B. K-Means Clustering Module

- **File**: `src/kmeans_clustering.py`
- **Responsibility**: Perform unsupervised clustering on processed vulnerability vectors to uncover natural groupings and patterns across vulnerabilities.
- **Input**:
  - `data/processed/vulnerabilities_processed.csv`
- **Expected Output**:
  - `artifacts/kmeans/cluster_assignments.csv`
- **Required Columns**:
  - `vuln_id`
  - `system_id`
  - `cluster_id` (integer cluster index)
- **Important Note**: K-Means clusters represent structural patterns, **not** severity ratings. Clusters do not automatically map to `Low`, `Medium`, `High`, or `Critical`; their security meaning is evaluated during analysis.

---

### C. KNN Classifier Module

- **File**: `src/knn_classifier.py`
- **Responsibility**: Train a K-Nearest Neighbors classifier to predict categorical risk levels for vulnerabilities based on their feature similarities to labeled historical cases.
- **Input**:
  - `data/processed/vulnerabilities_processed.csv`
- **Expected Output**:
  - `artifacts/knn/predictions.csv`
- **Required Columns**:
  - `vuln_id`
  - `system_id`
  - `actual_risk`
  - `predicted_risk` (Allowed values: `Low`, `Medium`, `High`, `Critical`)
  - `confidence` *(optional / added later)*

---

### D. Graph Builder Module

- **File**: `src/graph_builder.py`
- **Responsibility**: Construct the directed enterprise topology graph from network configuration data and overlay predicted vulnerability risks onto their corresponding network nodes.
- **Inputs**:
  - `data/network/network.json`
  - `artifacts/knn/predictions.csv` *(in later pipeline integration)*
- **Expected Output**:
  - Risk-weighted network graph structure (in-memory NetworkX graph object / graph representation).

---

### E. A* Search Module

- **File**: `src/astar_search.py`
- **Responsibility**: Apply the A* search algorithm over the risk-weighted network graph to identify the most concerning attack path from an untrusted entry point to critical internal assets.
- **Input**:
  - Risk-weighted network graph (produced by Graph Builder)
- **Expected Output**:
  - `artifacts/astar/attack_path.json`
- **Expected Structure**:
  ```json
  {
    "start": "INTERNET",
    "goal": "DB01",
    "path": ["INTERNET", "WEB01", "APP01", "DB01"],
    "total_cost": 0
  }
  ```
  *(Note: Exact cost evaluation formula and heuristic function will be defined in subsequent development stages.)*

---

### F. CSP Solver Module

- **File**: `src/csp_solver.py`
- **Responsibility**: Formulate remediation scheduling as a Constraint Satisfaction Problem (CSP) to assign patching tasks to teams and maintenance windows without violating operational limits.
- **Inputs**:
  - Identified attack path (`artifacts/astar/attack_path.json`)
  - Vulnerability priorities / risk ratings
  - Available remediation teams
  - Maintenance time slots
  - Operational constraints (e.g., maximum simultaneous outages, system dependencies)
- **Expected Output**:
  - `artifacts/csp/patch_schedule.json`
- **Example Structure**:
  ```json
  [
    {
      "vuln_id": "V001",
      "system_id": "WEB01",
      "team": "Team-A",
      "time_slot": "Monday-10AM",
      "status": "Scheduled"
    }
  ]
  ```

---

### G. Explainability Module

- **File**: `src/explainability.py`
- **Responsibility**: Generate human-interpretable rationales in plain English explaining:
  - Why a given vulnerability received a specific risk prediction.
  - Why a specific network route was chosen as the most critical attack path.
  - Why certain vulnerabilities were assigned higher remediation priority.

---

### H. Dashboard Module

- **File**: `dashboard/app.py`
- **Responsibility**: Interactive Streamlit user interface to display project results to stakeholders and examiners.
- **Planned Sections**:
  1. **Overview**: Executive summary, system topology summary, and key risk metrics.
  2. **Clusters**: Visual breakdown of K-Means groupings.
  3. **Risk Prediction**: KNN prediction table, confusion matrix, and feature distributions.
  4. **Attack Graph**: Interactive network graph highlighting detected A* attack paths.
  5. **Patch Plan**: Remediation schedule table and Gantt-style timeline.
  6. **What-If Analysis**: Scenario simulation (e.g., impact of patching a specific node on attack feasibility).

---

## Team File Ownership

To prevent merge conflicts and maintain clear responsibility, each primary project file is assigned to a designated team member:

| Role | Member | Primary Assigned Files |
|---|---|---|
| **Data & Unsupervised ML** | Member 2 | `src/preprocessing.py`<br>`src/kmeans_clustering.py` |
| **Supervised Classification** | Member 3 | `src/knn_classifier.py` |
| **Network & Search** | Member 4 | `src/graph_builder.py`<br>`src/astar_search.py` |
| **Planning & UI** | Member 5 | `src/csp_solver.py`<br>`src/explainability.py`<br>`dashboard/app.py` |
| **Architecture & Lead** | Team Lead | `main.py`<br>`src/risk_engine.py`<br>`src/utils.py`<br>`docs/`<br>Final Integration & Review |

### Collaboration Rules

- **Code Boundaries**: Members should avoid editing another member's primary files without prior team alignment.
- **Shared Contracts**: Any modification to input/output files or schemas must first be proposed, reviewed, and approved in `docs/DATA_SCHEMA.md` and `docs/MODULE_CONTRACTS.md`.
- **Branching Workflow**: All development occurs on feature branches branched from `dev`, followed by Pull Requests targeting `dev`.

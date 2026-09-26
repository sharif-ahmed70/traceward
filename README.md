# TraceWard: Intelligent Cybersecurity Risk Analysis, Attack Path Detection & Smart Remediation Planning

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests Passing](https://img.shields.io/badge/tests-430%20passed-success.svg)](tests/)
[![Architecture](https://img.shields.io/badge/architecture-modular%20pipeline-brightgreen.svg)](docs/MODULE_CONTRACTS.md)
[![UI](https://img.shields.io/badge/dashboard-Streamlit-red.svg)](dashboard/app.py)

---

## 1. Problem Statement

Modern enterprise Security Operations Centers (SOC) face significant challenges in vulnerability management:
- **CVSS Score Overload & Alert Fatigue**: Raw CVSS severity scores fail to account for specific enterprise topology, asset criticality, or active network exposure, leading to inefficient triage.
- **Topology-Blind Prioritization**: High-severity vulnerabilities situated on isolated, non-routed hosts often receive urgent attention while moderate flaws located on critical perimeter ingress corridors are neglected.
- **Remediation Bottlenecks & Operational Constraints**: Security teams cannot patch all flaws simultaneously. Patch deployment must respect specialized team qualifications, capacity limits, and prerequisite dependency orderings (e.g., perimeter firewalls before internal application servers).
- **Opaque Decision-Making**: Black-box algorithmic models provide vulnerability predictions without transparent, human-verifiable rationales, making it difficult for CISOs to justify downtime or maintenance windows to business executives.

**TraceWard** addresses these challenges by integrating **machine learning risk prediction**, **unsupervised structural clustering**, **topological graph search (A\*)**, and **constraint satisfaction programming (CSP)** into an explainable defensive cybersecurity decision-support framework.

---

## 2. System Architecture & Workflow

TraceWard operates as a cohesive, deterministic 8-stage pipeline where each module communicates through strict data schemas and interface contracts:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              TraceWard Integrated Pipeline                             │
└────────────────────────────────────────────────────────────────────────────────────────┘

    1. Raw Vulnerabilities (1,200 records) & Enterprise Topology (8 nodes, 9 edges)
                           │
                           ▼
    2. Preprocessing & Feature Engineering (7 CVSS dimensions, zero target leakage)
                           │
                           ▼
    3. Supervised KNN Risk Classifier (Stratified 5-Fold CV on Train; Best K=3)
       ├── Evaluation: 73.75% Test Accuracy, 0.7298 Weighted F1-Score
       └── Export: predictions.csv (240 test instances)
                           │
                           ▼
    4. Risk Engine Aggregation (Normalized risk score calculation per host system)
                           │
                           ▼
    5. Unsupervised K-Means Clustering (K=4 structural profiles via 2nd derivative elbow)
                           │
                           ▼
    6. Risk-Weighted Attack Graph Construction (Directed topology with dynamic friction)
                           │
                           ▼
    7. A* Search Attack Path Detection (Minimum defensive resistance corridor, Cost: 4.08)
                           │
                           ▼
    8. Backtracking CSP Remediation Planner (Team qualification & temporal prerequisites)
       ├── Solves feasible patch schedule (5 critical corridor tasks scheduled)
       └── Tracks pending operational backlog (235 items queued)
                           │
                           ▼
    9. Structured Explainability Engine (Exploitability vs. CIA Impact attribution)
                           │
                           ▼
    10. Interactive Streamlit Dashboard (7 comprehensive operational tabs)
```

---

## 3. Major Features

### 🛡️ Vulnerability Risk Prediction (Supervised KNN)
- Evaluates 7 standardized CVSS v3.1 security dimensions (Attack Complexity, Privileges Required, User Interaction, Confidentiality Impact, Integrity Impact, Availability Impact, and Exploit Probability).
- Employs Stratified 5-Fold Cross-Validation on the training partition ($N=960$) to prevent data leakage (`StandardScaler` fitted strictly within cross-validation folds).
- Predicts categorical severity (`Low`, `Medium`, `High`, `Critical`) with **73.75% held-out test accuracy** and **0.7298 weighted F1-score**.

### 🔍 Structural Vulnerability Clustering (Unsupervised K-Means)
- Groups vulnerabilities into **4 distinct structural profiles** based on feature geometry rather than severity labels.
- Evaluates candidates $K \in [2, 8]$ using the discrete centered second difference of inertia ($D^2 = 189.30$ at $K=4$) and silhouette analysis.
- Differentiates automated network exploits from user-interaction-dependent attacks.

### 🌐 Risk-Weighted Attack Path Detection (A* Search)
- Constructs a directed enterprise graph (8 nodes: 1 untrusted `INTERNET` ingress + 7 host systems; 9 directed edges).
- Implements dynamic traversal edge impedance: $c(u, v) = \max(0.5, \text{round}(2.0 - \text{Risk}(v), 2))$.
- Computes the critical breach corridor from `INTERNET` to crown-jewel database `DB01`:
  $$\text{INTERNET} \xrightarrow{c=1.37} \text{WEB01} \xrightarrow{c=1.35} \text{APP01} \xrightarrow{c=1.36} \text{DB01} \quad (\text{Total Cost: } 4.08)$$
- Defensibly demonstrates why the 3-hop corridor represents the path of least resistance over the 5-hop VPN route (Cost: 6.85).

### 📋 Constraint-Based Remediation Planning (Backtracking CSP)
- Formulates patch scheduling as a formal Constraint Satisfaction Problem:
  - **Constraint 1 (Team Specialization)**: Tasks are assigned exclusively to qualified operational teams (Web, Application, Database, Network).
  - **Constraint 2 (Resource Capacity)**: Strictly zero team multitasking (max 1 task per team per operational slot).
  - **Constraint 3 (Defensive Prerequisites)**: Boundary/perimeter fixes must strictly precede internal application fixes (`APP01` depends on `WEB01`; `BACKUP01` depends on `DB01`).
- Generates a feasible schedule across operational windows and explicitly tracks non-scheduled items in a pending backlog.

### 💡 Structured Explainability Engine (XAI)
- **Multi-Factor Attribution**: Deconstructs risk ratings into Exploitability and CIA Impact subscores with qualitative directional rationale.
- **Asset Contextualization**: Integrates host criticality (Levels 1–5), exposure scope (Perimeter vs. Internal), and operational roles.
- **Breach Corridor Alignment**: Classifies host roles in the Cyber Kill Chain (Perimeter Foothold, Lateral Pivot, Crown Jewel Target).
- **Scheduling Justification**: Explains the exact temporal and prerequisite factors determining slot assignment.

### 🧪 What-If Security Simulation
- Allows defensive operators to simulate host-level hardening (10% to 90% risk reduction).
- Evaluates the quantitative defensive gain ($+\Delta$ traversal cost) on an isolated in-memory deep copy without modifying disk baselines or severing graph connectivity.

---

## 4. Technology Stack

| Component | Technology | Version / Spec |
| :--- | :--- | :--- |
| **Language** | Python | 3.11+ |
| **Machine Learning** | scikit-learn | 1.9+ (`KNeighborsClassifier`, `KMeans`, `StandardScaler`, `Pipeline`) |
| **Data Processing** | pandas, NumPy | High-performance tabular transformation and matrix manipulation |
| **Graph Modeling** | NetworkX | Directed graph topology and risk-weighted adjacency structures |
| **Web Dashboard** | Streamlit | Real-time multi-tab cybersecurity command center |
| **Visualization** | Graphviz / Matplotlib | Directed attack graphs and ML evaluation curves (Elbow, Confusion Matrix) |
| **Serialization** | Joblib / JSON / CSV | Contract-compliant artifact persistence |
| **Testing** | Python `unittest` | Automated regression test suite (430 tests) |

---

## 5. Verified Project Statistics

| Metric | Measured Value | Verification Source |
| :--- | :--- | :--- |
| **Total Vulnerability Records** | **1,200 records** | `data/raw/vulnerabilities.csv` (300 per class balanced) |
| **Enterprise Network Systems** | **7 hosts + 1 entry** | `data/network/network.json` (8 nodes, 9 directed edges) |
| **Security Feature Dimensions** | **7 CVSS dimensions** | 6 ordinal (0..2) + 1 continuous (0.0..1.0) |
| **Supervised Model Quality** | **73.75% Acc / 0.7298 F1** | Stratified 80/20 train/test split ($N=240$ test set) |
| **Structural Clusters** | **4 clusters ($K=4$)** | Discrete second difference elbow ($D^2=189.30$) |
| **Critical Attack Path Cost** | **4.08 (3 hops)** | `artifacts/astar/attack_path.json` |
| **Scheduled Tasks vs. Backlog** | **5 scheduled / 235 backlog** | `artifacts/csp/patch_schedule.json` |
| **Automated Test Coverage** | **430 passed (0 errors)** | Full test suite across 18 modules |
| **Dashboard Navigation** | **7 interactive tabs** | `dashboard/app.py` |

---

## 6. Repository Structure

```
traceward/
├── artifacts/                  # Generated model artifacts and pipeline outputs
│   ├── astar/                  # A* critical attack path JSON
│   ├── csp/                    # Scheduled patch plan JSON
│   ├── kmeans/                 # Cluster assignments, profiles, elbow & silhouette plots
│   ├── knn/                    # Fitted model pipeline, predictions, confusion matrix
│   └── risk/                   # System risk summaries
├── data/
│   ├── network/                # Network topology definition (network.json)
│   ├── processed/              # Cleaned, ordinally encoded feature dataset
│   └── raw/                    # Raw vulnerability records (1,200 rows)
├── dashboard/
│   ├── app.py                  # Streamlit multi-tab web application
│   └── ui.py                   # Cyber command-center design system & Graphviz visualizer
├── docs/
│   ├── DATA_SCHEMA.md          # Formal data schema definitions
│   ├── FINBANK_SIMULATION.md   # FinBank incident simulation documentation
│   ├── MODULE_CONTRACTS.md     # Module interface and contract specifications
├── src/
│   ├── astar_search.py         # A* risk-aware shortest path search
│   ├── csp_solver.py           # Backtracking Constraint Satisfaction Problem solver
│   ├── explainability.py       # Structured Explainability Engine (XAI)
│   ├── graph_builder.py        # Network topology & risk-weighted graph constructor
│   ├── kmeans_clustering.py    # K-Means clustering, elbow heuristic & silhouette analysis
│   ├── knn_classifier.py       # Supervised KNN risk classifier with Stratified 5-Fold CV
│   ├── preprocessing.py        # Ordinal encoding & feature engineering
│   ├── risk_engine.py          # Asset risk calculation & host-level aggregation
│   ├── finbank_env.py          # FinBank environment configuration
│   ├── finbank_assignment.py   # Deterministic vulnerability inventory assignment
│   ├── finbank_simulation.py   # Unified FinBank simulation pipeline
│   ├── finbank_network.py      # FinBank topology graph construction
│   ├── finbank_astar_integration.py  # FinBank A* attack path analysis
│   ├── finbank_csp_planner.py  # FinBank CSP remediation planning
│   ├── what_if_simulation.py   # Isolated system hardening simulator
├── tests/                      # Automated unit and integration test suites (430 tests)
│   ├── test_explainability.py
│   ├── test_foundation_integration.py
│   ├── test_finbank_assignment.py
│   ├── test_finbank_astar_integration.py
│   ├── test_finbank_comprehensive.py
│   ├── test_finbank_csp_planner.py
│   ├── test_finbank_env.py
│   ├── test_finbank_incident_predictor.py
│   ├── test_finbank_network.py
│   ├── test_finbank_predictor.py
│   ├── test_finbank_scenarios.py
│   ├── test_finbank_simulation.py
│   ├── test_finbank_simulator.py
│   ├── test_kmeans_clustering.py
│   ├── test_knn_classifier.py
│   ├── test_member5.py
│   ├── test_preprocessing.py
│   ├── test_risk_engine.py
│   └── test_what_if.py
├── DEMO_GUIDE.md               # Faculty viva presentation script & technical Q&A
├── main.py                     # Master execution pipeline
├── README.md                   # Project documentation
└── requirements.txt            # Python dependencies
```

---

## 7. Running Instructions

### Step 1: Environment Setup
Ensure Python 3.11+ is installed. Create and activate a virtual environment:

```powershell
# Create virtual environment
python -m venv .venv

# Activate on Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Install project dependencies
pip install -r requirements.txt
```

### Step 2: Run the End-to-End Pipeline
Execute the full 8-stage data engineering, machine learning, graph search, and remediation workflow:

```powershell
python main.py
```
*(Executes data validation, preprocessing, KNN training & evaluation, risk aggregation, K-Means clustering, attack graph generation, A\* path detection, and CSP scheduling in ~5 seconds).*

### Step 3: Run the Automated Test Suite
Verify module contracts, zero data leakage, and system integrity:

```powershell
python -m unittest discover -v -s tests -p "test_*.py"
```
*(Runs all 430 unit and integration tests across 18 test suites).*

### Step 4: Launch the Interactive Dashboard
Start the local Streamlit command center:

```powershell
streamlit run dashboard/app.py
```
*(Opens the interactive application in your default browser at `http://localhost:8501`).*

---

## 8. Dashboard Walkthrough

1. **Dataset / Foundation**: Inspects raw and processed records, balanced class distributions (300/class), and enterprise network topology.
2. **Risk Prediction**: Explores held-out test predictions and features an **Interactive Model Inference form** allowing users to submit custom CVSS vectors to observe real-time KNN classification and feature attribution.
3. **Structural Clusters**: Displays discrete second-difference elbow analysis ($K=4$), silhouette curves, and descriptive profile radar charts.
4. **Attack Graph / Path**: Renders the directed topology graph with the critical A* corridor highlighted in crimson, accompanied by Kill Chain stage progression and threat details.
5. **Patch Plan**: Presents the feasible CSP maintenance schedule, backlog statistics, explainable justification cards, and an interactive **Infeasibility Simulation** test.
6. **What-If Scenario Simulation**: Empowers security leads to model the defensive traversal friction gain from hardening any enterprise system.
7. **Incident Simulation**: Runs deterministic FinBank attack scenarios end-to-end, producing fictional attack sequences, affected systems, estimated vulnerability risk, potential attack routes, and suggested remediation schedules.

---

## 9. Academic Context

**Project**: TraceWard — Intelligent Cybersecurity Decision Support Framework  
**Course**: Artificial Intelligence Laboratory  
**Department**: Computer Science & Engineering  
**Focus**: Machine Learning (KNN, K-Means), Heuristic Search (A\*), Constraint Satisfaction (CSP), and Explainable AI (XAI).

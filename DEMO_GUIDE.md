# TraceWard — Faculty Demonstration Guide

## A. Project Overview

**TraceWard: Cyber Risk Analysis, Attack Path Detection & Smart Remediation Planning**

TraceWard is an intelligent defensive cybersecurity decision-support framework designed to bridge the gap between individual vulnerability discoveries and enterprise-level risk mitigation. It integrates machine learning, graph search, and constraint programming:

1. **Vulnerability Classification**: Predicts vulnerability risk ratings from 7 security characteristics using supervised K-Nearest Neighbors (KNN).
2. **Structural Clustering**: Identifies vulnerability feature profiles via unsupervised K-Means.
3. **Risk Aggregation**: Aggregates asset-level risk metrics into system risk profiles.
4. **Defensive Path Detection**: Evaluates network topology via A* search to uncover critical traversal routes toward crown-jewel assets.
5. **Smart Remediation Planning**: Generates feasible, operational patch schedules through Backtracking Constraint Satisfaction Problems (CSP).
6. **Transparent Explainability**: Delivers plain-English rationales for every risk rating and remediation decision.

---

## B. Complete Demonstration Flow

```
1. Dataset Validation  ──> Validates 1,200 vulnerability records and 8-node network topology
         │
2. Preprocessing       ──> Encodes 7 categorical security features into normalized numeric space
         │
3. KNN Risk Prediction ──> Trains stratified classifier, selects K=9, evaluates on 240 held-out test cases
         │
4. K-Means Clustering  ──> Partitions vulnerabilities into 4 structural profile clusters
         │
5. Risk Aggregation    ──> Calculates normalized risk scores and highest severity across all systems
         │
6. Attack Graph Gen    ──> Constructs directed enterprise topology overlaid with system risk weights
         │
7. A* Attack Path      ──> Finds the critical attack path from INTERNET to DB01 (Cost: 4.03)
         │
8. CSP Remediation     ──> Solves Backtracking CSP to generate feasible team-slot maintenance schedules
         │
9. Explainability      ──> Translates model predictions into human-verifiable security evidence
         │
10. Dashboard Visuals  ──> Interactive 6-tab Streamlit dashboard for stakeholder inspection
```

---

## C. Exact Demonstration Commands

### Step 1: Run the End-to-End Pipeline
```powershell
python main.py
```
*(Runs the entire end-to-end data, ML, graph, CSP, and explainability workflow).*

### Step 2: Run the Automated Regression Test Suite
```powershell
python -m unittest discover -v -s tests -p "test_*.py"
```
*(Executes all 60 automated unit and integration tests across 6 test modules).*

### Step 3: Launch the Interactive Dashboard
```powershell
python -m streamlit run dashboard/app.py
```
*(Opens the interactive web application at `http://localhost:8501`).*

---

## D. Understanding the Pipeline Outputs

### 1. Foundation Validation Output
```text
[1/8] Validating foundation datasets & network...
      Foundation Status: READY
      Raw vulnerabilities: 1200
      Processed vulnerabilities: 1200
      Network nodes: 8
      Network edges: 9
```
* **Meaning**: Confirms data integrity across the repository. 1,200 raw vulnerability records cleanly match 1,200 preprocessed rows without missing values. All system IDs map strictly to existing nodes in `data/network/network.json`.

### 2. Preprocessing Output
```text
[2/8] Preprocessing verification...
      Input features: 7 security dimensions ready for ML.
```
* **Meaning**: Confirms ordinal encoding of the 7 agreed security dimensions (`attack_complexity`, `privileges_required`, `user_interaction`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `exploit_probability`). Non-feature fields (`vuln_id`, `system_id`, `description`) are strictly separated to prevent target leakage.

### 3. KNN Risk Classifier Output
```text
[3/8] Training KNN Risk Classifier & Generating Predictions...
      Selected K=9 with test accuracy=0.7792
      Accuracy:  0.7792 | Precision: 0.7826 | Recall: 0.7792 | F1-Score: 0.7682
      Saved: artifacts/knn/predictions.csv (240 test predictions)
```
* **Meaning**: The KNN classifier tested multiple neighborhood sizes ($K \in \{3, 5, 7, 9\}$) and selected $K=9$ as optimal. It evaluated 240 held-out test samples with ~78% accuracy and F1 score of 0.768. `StandardScaler` was fit strictly on the training set to prevent data leakage.

### 4. Risk Engine Aggregation Output
```text
[4/8] Aggregating System Risk Scores...
      Summarized 7 systems by risk severity:
        - DB01: Normalized Risk=0.680, Highest=Critical
        - BACKUP01: Normalized Risk=0.661, Highest=Critical
        - WEB01: Normalized Risk=0.651, Highest=Critical
        - APP01: Normalized Risk=0.644, Highest=Critical
```
* **Meaning**: Aggregates individual vulnerability predictions into actionable system risk levels. `normalized_risk` scales from 0.25 to 1.0. Database server `DB01` has the highest aggregate vulnerability severity.

### 5. K-Means Structural Clustering Output
```text
[5/8] Running K-Means Structural Clustering...
      Vulnerabilities grouped into 4 structural profiles.
      Saved: artifacts/kmeans/cluster_assignments.csv
```
* **Meaning**: Partitions vulnerabilities into 4 structural behavior profiles. Clusters represent architectural and attack pattern similarities, not severity labels.

### 6. Attack Graph Generation Output
```text
[6/8] Generating Risk-Weighted Attack Graph...
      Constructed topology with 8 systems and 9 directed edges.
```
* **Meaning**: Builds the directed enterprise network graph and overlays the system risk scores onto graph nodes.

### 7. A* Search Attack Path Output
```text
[7/8] Running A* Search for Critical Attack Path...
      Critical Path Identified: INTERNET -> WEB01 -> APP01 -> DB01
      Accumulated Path Cost: 4.03
      Saved: artifacts/astar/attack_path.json
```
* **Meaning**: Uses A* search with an admissible heuristic to determine the most concerning traversal path from the untrusted entry point (`INTERNET`) to crown-jewel assets (`DB01`). Traversal cost is lower where systems have higher vulnerability risk.

### 8. CSP Remediation Plan Output
```text
[8/8] Solving Constraint Satisfaction Problem (CSP) for Remediation...
      Remediation Solver: Backtracking CSP (Status: feasible)
      Generated Feasible Patch Schedule:
        - Mon 09:00: Web Team -> VULN-001 (Critical on WEB01)
        - Mon 09:00: Database Team -> VULN-002 (High on DB01)
        - Mon 09:00: Network Team -> VULN-005 (Medium on VPN01)
        - Mon 14:00: Application Team -> VULN-003 (High on APP01)
        - Mon 14:00: Database Team -> VULN-004 (Medium on BACKUP01)
      Saved: artifacts/csp/patch_schedule.json
```
* **Meaning**: The Backtracking CSP solver finds a feasible maintenance schedule ensuring:
  1. Each task is assigned to its required team.
  2. No team has overlapping tasks in the same time slot.
  3. Prerequisite vulnerability dependencies are resolved before dependent tasks.

### 9. Explainability Output
```text
Explainability Sample:
  Predicted risk for V1136 on DB01: Critical.
```
* **Meaning**: Shows transparent, human-readable evidence for the automated prediction, detailing contributing security factors and cluster context.

### 10. Interactive Streamlit Dashboard Visuals
* **Overview Tab**: Key executive metrics (total vulnerabilities, affected systems, risk distributions, active patch tasks).
* **Clusters Tab**: Interactive table of K-Means cluster assignments with system breakdown summaries.
* **Risk Prediction Tab**: Selectable vulnerability dropdown displaying real-time explainability rationales.
* **Attack Graph/Path Tab**: Visual display of the selected A* path (`INTERNET -> WEB01 -> APP01 -> DB01`) and defensive explanations.
* **Patch Plan Tab**: Interactive schedule matrix showing assigned teams, time slots, and expandable CSP constraints.
* **What-If Analysis Tab**: Interactive scenario controls allowing simulated adjustments to priority and team availability.

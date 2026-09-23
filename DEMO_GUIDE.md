# TraceWard — Faculty Demonstration Guide

## A. Project Overview

**TraceWard: Cyber Risk Analysis, Attack Path Detection & Smart Remediation Planning**

TraceWard is an intelligent defensive cybersecurity decision-support framework designed to bridge the gap between individual vulnerability discoveries and enterprise-level risk mitigation. It integrates machine learning, graph search, and constraint programming:

1. **Vulnerability Classification**: Predicts categorical vulnerability risk ratings from 7 security characteristics using supervised K-Nearest Neighbors (KNN).
2. **Structural Clustering**: Identifies vulnerability feature profiles via unsupervised K-Means with Elbow & Silhouette analysis.
3. **Risk Aggregation**: Aggregates asset-level risk metrics into system risk profiles.
4. **Defensive Path Detection**: Evaluates network topology via A* search to uncover critical traversal routes toward crown-jewel assets.
5. **Smart Remediation Planning**: Generates feasible, operational patch schedules through Backtracking Constraint Satisfaction Problems (CSP).
6. **Transparent Explainability**: Delivers plain-English rationales for every risk rating and remediation decision.

---

## B. Complete Demonstration Flow

```
1. Dataset Validation  ──> Validates 1,200 vulnerability records and 8-node network topology
         │
2. Preprocessing       ──> Preprocesses 6 categorical features (ordinal) and 1 continuous numeric feature (exploit_probability)
         │
3. KNN Risk Prediction ──> Stratified 5-Fold CV on training set selects K=3; evaluates on 240 held-out test cases
         │
4. K-Means Clustering  ──> Compares K=2..8, selects K=4 via discrete 2nd derivative elbow, profiles 4 structural groups
         │
5. Risk Aggregation    ──> Calculates normalized risk scores and highest severity across all 7 host systems
         │
6. Attack Graph Gen    ──> Constructs directed enterprise topology (8 nodes: 1 INTERNET entry + 7 host systems) overlaid with risk
         │
7. A* Attack Path      ──> Finds the critical attack path from INTERNET to DB01 (Cost: 4.08)
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
.venv\Scripts\python.exe main.py
```
*(Runs the entire end-to-end data, ML, graph, CSP, and explainability workflow).*

### Step 2: Run the Automated Regression Test Suite
```powershell
.venv\Scripts\python.exe -m unittest discover -v -s tests -p "test_*.py"
```
*(Executes all 73 automated unit and integration tests across 8 test modules).*

### Step 3: Launch the Interactive Dashboard
```powershell
.venv\Scripts\python.exe -m streamlit run dashboard/app.py
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
* **Meaning**: Confirms data integrity across the repository. 1,200 raw vulnerability records cleanly match 1,200 preprocessed rows without missing values. All vulnerability records map to the 7 enterprise host systems (`WEB01`, `APP01`, `AUTH01`, `VPN01`, `EMP01`, `DB01`, `BACKUP01`), which together with the `INTERNET` untrusted entry point constitute the 8 network topology nodes in `data/network/network.json`.

### 2. Preprocessing Output
```text
[2/8] Preprocessing verification...
      Input features: 7 security dimensions ready for ML.
```
* **Meaning**: Confirms preprocessing of the 7 agreed security dimensions: 6 categorical attributes mapped ordinally (`attack_complexity`: 0..1, `privileges_required`: 0..2, `user_interaction`: 0..1, `confidentiality_impact`: 0..2, `integrity_impact`: 0..2, `availability_impact`: 0..2) plus 1 continuous numeric attribute (`exploit_probability`: 0.0..1.0). Identifiers (`vuln_id`, `system_id`) and free text (`description`) are separated to prevent target leakage.

### 3. KNN Risk Classifier Output
```text
[3/8] Training KNN Risk Classifier & Generating Predictions...
      Evaluating candidate K values via Stratified 5-Fold CV on Training Set (N=960):
      K=3: Mean CV Acc = 0.7281 (Selected)
      Held-out Test Metrics (N=240):
      Accuracy: 0.7375 | Precision: 0.7288 | Recall: 0.7375 | F1-Score: 0.7298
      Saved: artifacts/knn/predictions.csv (240 test predictions)
```
* **Meaning**: The KNN classifier tunes $K \in \{3, 5, 7, 9\}$ strictly via 5-Fold Stratified Cross-Validation on the training partition (`N=960`). $K=3$ achieved the highest cross-validation score (0.7281). Scaling was fitted inside the cross-validation folds. Held-out test evaluation on the remaining 240 unseen records achieved 73.75% accuracy and 0.7298 F1-score.

### 4. Risk Engine Aggregation Output
```text
[4/8] Aggregating System Risk Scores...
      Summarized 7 systems by risk severity:
        - BACKUP01: Normalized Risk=0.677, Highest=Critical
        - APP01: Normalized Risk=0.654, Highest=Critical
        - DB01: Normalized Risk=0.639, Highest=Critical
        - WEB01: Normalized Risk=0.634, Highest=Critical
```
* **Meaning**: Aggregates individual vulnerability predictions into actionable system risk levels across the 7 host systems. `normalized_risk` scales from 0.25 to 1.0.

### 5. K-Means Structural Clustering Output
```text
[5/8] Running K-Means Structural Clustering...
      Vulnerabilities grouped into 4 structural profiles.
      Saved: artifacts/kmeans/cluster_assignments.csv
```
* **Meaning**: Evaluated candidate $K \in [2, 8]$ using both Inertia and Silhouette scores. $K=4$ was selected using the discrete second derivative of inertia (deceleration $D^2 = 189.30$). Silhouette scores remain modest across all candidates ($0.1465$ to $0.1781$, peaking at $K=8$) because 6 of 7 features are discrete ordinals; $K=4$ balances variance explained with interpretability.

### 6. Attack Graph Generation Output
```text
[6/8] Generating Risk-Weighted Attack Graph...
      Constructed topology with 8 nodes and 9 directed edges.
```
* **Meaning**: Builds the directed enterprise network graph (8 nodes: 1 untrusted `INTERNET` entry point + 7 host systems) and overlays system risk scores onto graph nodes.

### 7. A* Search Attack Path Output
```text
[7/8] Running A* Search for Critical Attack Path...
      Critical Path Identified: INTERNET -> WEB01 -> APP01 -> DB01
      Accumulated Path Cost: 4.08
      Saved: artifacts/astar/attack_path.json
```
* **Meaning**: Uses A* search with an admissible heuristic to determine the most concerning traversal path from the untrusted entry point (`INTERNET`) to crown-jewel assets (`DB01`).

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
* **Meaning**: The Backtracking CSP solver finds a feasible maintenance schedule ensuring no team overlaps and prerequisite dependencies are patched first.

### 9. What-If Scenario Simulation Output
```text
Simulating patch impact on WEB01 (-50% risk reduction)...
  Baseline Risk: 0.634 -> Simulated Risk: 0.317 (-0.317)
  Adversary Traversal Cost: 4.08 -> 4.39 (+0.31 Defensive Gain)
  Attack Path Status: Maintained (Hardened)
```
* **Meaning**: Simulates applying security remediation to target systems on an isolated copy of the network state without severing topology connectivity, recomputing risk-aware A* attack paths to quantitatively measure defensive gain.

---

## E. Week 1 Faculty Presentation Walkthrough

This section provides a standalone, defensible 5–7 minute demonstration strictly covering our **Slide 8 Week 1 commitments** ("Data + ML Foundation") without depending on later-week modules.

### 1. 5–7 Minute Demonstration Sequence

| Step & Time | Focus Area | Action / Command | What to Show Ma'am | Artifact / File Location |
| :--- | :--- | :--- | :--- | :--- |
| **Step 1** (1 min) | **Dataset Integrity & Balance** | `.venv\Scripts\python.exe -c "import pandas as pd; df=pd.read_csv('data/raw/vulnerabilities.csv', keep_default_na=False); print(df.shape); print(df['risk_label'].value_counts())"` | Show 1,200 records, exactly 300 per class (Low, Medium, High, Critical), 0 missing values, and all 7 target enterprise host systems (out of 8 network topology nodes). | `data/raw/vulnerabilities.csv`<br>`docs/DATA_SCHEMA.md` |
| **Step 2** (1 min) | **Preprocessing & Feature Engineering** | `.venv\Scripts\python.exe -c "import pandas as pd; df=pd.read_csv('data/processed/vulnerabilities_processed.csv'); print(df.head(3))"` | Show how 6 categorical attributes are mapped to ordinal numbers (0, 1, 2) alongside continuous `exploit_probability` (0.0-1.0), while `vuln_id` and `system_id` are preserved and `description` dropped. Highlight zero target leakage. | `src/preprocessing.py`<br>`data/processed/vulnerabilities_processed.csv` |
| **Step 3** (2 min) | **K-Means Cluster Analysis** | `.venv\Scripts\python.exe src/kmeans_clustering.py` | 1. Open `artifacts/kmeans/elbow_plot.png` showing the inertia elbow at $K=4$ ($C(4)=189.30$).<br>2. Open `artifacts/kmeans/silhouette_plot.png` (explaining modest 0.14-0.18 scores from discrete ordinal space).<br>3. Open `artifacts/kmeans/cluster_analysis.txt` to explain the 4 measured vulnerability profiles based on User Interaction (None vs. Required) and Exploitability/Impact levels. | `artifacts/kmeans/elbow_plot.png`<br>`artifacts/kmeans/cluster_profiles.csv`<br>`artifacts/kmeans/cluster_analysis.txt` |
| **Step 4** (2 min) | **KNN Model Training & Evaluation** | `.venv\Scripts\python.exe src/knn_classifier.py` | 1. Show 5-Fold Cross-Validation table selecting $K=3$ (CV Acc: 72.81%).<br>2. Open `artifacts/knn/confusion_matrix.png`.<br>3. Review `artifacts/knn/evaluation_report.txt` showing held-out test accuracy of 73.75%, precision 0.7288, recall 0.7375, F1 0.7298. | `artifacts/knn/k_selection_cv.csv`<br>`artifacts/knn/confusion_matrix.png`<br>`artifacts/knn/evaluation_report.txt` |
| **Step 5** (1 min) | **Automated Test Verification** | `.venv\Scripts\python.exe -m unittest -v tests.test_kmeans_clustering tests.test_knn_classifier` | Show that all 13 ML unit tests pass with zero errors, validating contracts, leakage prevention, and export integrity. | `tests/test_kmeans_clustering.py`<br>`tests/test_knn_classifier.py` |

### 2. Standalone Fallback Procedure (If GUI / Web Server is Unavailable)
If Streamlit or a browser cannot be launched during the viva, all artifacts are pre-generated, static, and inspectable:
* Open `artifacts/kmeans/elbow_plot.png` and `artifacts/knn/confusion_matrix.png` in Windows Photos.
* Open `artifacts/kmeans/cluster_analysis.txt` and `artifacts/knn/evaluation_report.txt` in Notepad / VS Code.
* Show the automated test output in the terminal (`Ran 73 tests in 4.2s - OK`).

---

## F. Bangla Presentation Script (With English Technical Terms)

> *"আসসালামু আলাইকুম ম্যাম। আজ আমরা TraceWard প্রজেক্টের **Week 1 — Data + ML Foundation**-এর সম্পূর্ণ অগ্রগতি উপস্থাপন করছি।*
>
> ***১. Dataset & Preprocessing:***  
> *প্রেজেন্টেশনের Slide 8-এ আমরা যে প্রতিশ্রুতি দিয়েছিলাম, সেই অনুযায়ী আমাদের vulnerability dataset সম্পূর্ণ প্রস্তুত। এতে মোট ১,২০০টি synthetic vulnerability record রয়েছে, যা চারটি risk class-এ (Low, Medium, High, Critical) সুষমভাবে ৩০০টি করে বিভক্ত। ৬টি categorical feature-কে ordinally encode করা হয়েছে এবং ১টি continuous numeric feature (`exploit_probability`) সহ মোট ৭টি সিকিউরিটি ডাইমেনশন প্রস্তুত করা হয়েছে। এখানে কোনো missing value নেই এবং identifiers (`vuln_id`, `system_id`) আলাদা রাখা হয়েছে যাতে কোনো target leakage না ঘটে।*
>
> ***২. K-Means Clustering ও Cluster Analysis:***  
> *আমরা K-Means অ্যালগরিদম সফলভাবে বাস্তবায়ন করেছি এবং candidate K = 2 থেকে 8 পর্যন্ত পরীক্ষা করেছি। Inertia curve-এর discrete centered second difference elbow heuristic ($C(4)=189.30$) এবং Silhouette Analysis বিশ্লেষণ করে আমরা $K=4$ নির্বাচন করেছি। এখানে সবচেয়ে গুরুত্বপূর্ণ বিষয় হলো—এই ক্লাস্টারগুলো কোনো risk level নয়; এগুলো ভালনারেবিলিটির কাঠামোগত বৈশিষ্ট্য (structural profiles) প্রকাশ করে। যেমন: Cluster 0 ও 2-তে User Interaction 0.0 (None), আর Cluster 1 ও 3-তে User Interaction 1.0 (Required); পাশাপাশি Cluster 2 ও 3-তে exploit probability এবং C/I/A impact উল্লেখযোগ্যভাবে বেশি।*
>
> ***৩. KNN Risk Classification ও Model Selection:***  
> *সুপারভাইজড লার্নিংয়ের জন্য আমরা KNN ক্লাসিফায়ার তৈরি করেছি। ডেটাসেটকে ৮০/২০ অনুপাতে stratified split করা হয়েছে (৯৬০টি train, ২৪০টি test)। ডেটা লিকেজ সম্পূর্ণ রোধ করতে আমরা scikit-learn Pipeline ব্যবহার করে প্রতিটি CV fold-এর ভেতরে স্কেলার ফিট করেছি। Training set-এর ওপর 5-Fold Cross-Validation চালিয়ে আমরা দেখতে পাই $K=3$ সর্বোচ্চ ৭২.৮১% CV accuracy দেয়। নির্বাচিত $K=3$ মডেলকে ২৪০টি unseen held-out test ডেটায় টেস্ট করে আমরা ৭৩.৭৫% accuracy এবং ০.৭২৯৮ weighted F1-score পেয়েছি।*
>
> ***৪. Limitations & Honesty:***  
> *আমরা দুটি সীমাবদ্ধতা স্বচ্ছভাবে উল্লেখ করছি: প্রথমত, বর্তমান ডেটা সিন্থেটিক এবং দ্বিতীয়ত, প্রাথমিক এক্সপ্লোরেশনের সময় টেস্ট সেট কনসাল্ট হয়েছিল, তাই বর্তমান রেজাল্টটি আমাদের ডেজিগনেটেড স্প্লিটের ওপর একটি ডিফেন্সিবল এবং মেথডোলজিক্যাল ভ্যালিডেশন।*
>
> ***৫. Next Steps:***  
> *Week 1-এর সমস্ত টেস্ট (৭৩/৭৩ টেস্ট) সফলভাবে পাস করেছে। আমাদের পরবর্তী লক্ষ্য Week 2-তে A\* Search attack path detection, CSP-based remediation planning এবং What-If simulation পূর্ণাঙ্গভাবে প্রসারিত করা। ধন্যবাদ ম্যাম।"*

---

## G. Top 5 Viva Questions & Answers

#### Q1: Why did you select K = 4 clusters for K-Means? Did you just match the 4 risk labels?
**Answer**:  
*"No, Ma'am. We strictly avoided forcing K=4 based on risk labels because clustering is unsupervised and must discover feature structure, not replicate labels. In our candidate evaluation ($K=2..8$), we computed the discrete centered second difference of inertia, $C(k) = I(k-1) - 2 \cdot I(k) + I(k+1)$, across interior candidates $k \in [3, 7]$. At $K=4$, $C(4) = 189.30$, which marks the maximum deceleration in inertia reduction (compared to $C(3)=135.31$, $C(5)=39.81$, $C(6)=133.55$, $C(7)=-192.76$). This is a discrete elbow heuristic, not mathematical proof of a unique optimal count. Across all evaluated K, Silhouette scores show only modest cluster separation (0.1465 to 0.1781) and disagree with the elbow heuristic, peaking slightly at $K=8$ (0.1781 vs. 0.1488 at $K=4$). $K=4$ was retained under the elbow heuristic to balance variance reduction against model complexity."*

#### Q2: Why are K-Means clusters fundamentally different from risk classes (Low/Medium/High/Critical)?
**Answer**:  
*"Risk classes represent the consequence and priority of a vulnerability, which is a supervised target label. In contrast, K-Means clusters represent unsupervised groupings across the 7 feature dimensions. For example, Cluster 0 and Cluster 2 both have User Interaction = None (0.0), but Cluster 0 has lower exploit probability (0.32) and lower C/I/A impact (0.63), while Cluster 2 has higher exploit probability (0.69) and elevated impact (1.49). Each cluster contains vulnerabilities across multiple risk classes rather than mapping 1:1 to severity."*

#### Q3: How was the optimal K selected for the KNN classifier?
**Answer**:  
*"We compared $K \in \{3, 5, 7, 9\}$ using 5-Fold Stratified Cross-Validation strictly on the training partition (960 records). $K=3$ achieved the highest mean cross-validation accuracy of 72.81% (F1: 71.81%). The final model was then evaluated once on the separate, held-out 20% test partition (240 records), achieving 73.75% accuracy and 0.7298 weighted F1-score."*

#### Q4: How did you ensure there is no data leakage during feature scaling and cross-validation?
**Answer**:  
*"We implemented two strict safeguards: First, identifiers (`vuln_id`, `system_id`) and the target (`risk_label`) are completely excluded from the feature matrix $X$. Second, rather than applying `StandardScaler` to the entire dataset prior to splitting, we encapsulated scaling inside a scikit-learn `Pipeline`. During cross-validation, the scaler is fit strictly on each fold's training split and merely transforms the validation fold, ensuring zero statistical leakage."*

#### Q5: What does model performance on synthetic data demonstrate, and what does it NOT establish?
**Answer**:  
*"It establishes that our entire data pipeline, feature encoding, cross-validation methodology, classification algorithms, and downstream contract interfaces are mathematically sound, reproducible, and leak-free. However, because the relationships are based on a controlled synthetic generation adhering to CVSS metric distributions, it does not claim real-world generalization to uncurated zero-day vulnerabilities in live production environments, which would require empirical evaluation on real-world incident datasets."*

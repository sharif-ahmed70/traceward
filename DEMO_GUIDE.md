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
*(Executes all 88 automated unit and integration tests across 8 test modules).*

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
* **Meaning**: Uses heuristic A* search over the risk-weighted topology graph. The edge traversal impedance is dynamically computed from destination host vulnerability exposure: $c(u, v) = \max(0.5, \text{round}(2.0 - \text{Risk}(v), 2))$. Higher risk yields lower traversal impedance, modeling the path of least resistance for an adversary.
* **Kill Chain Interpretation**:
  1. `INTERNET` (Cost: 0.00): Perimeter Ingress & External Exposure.
  2. `WEB01` (Step Cost: 1.37, Risk: 0.634): Initial Foothold & Boundary Ingress Compromise.
  3. `APP01` (Step Cost: 1.35, Risk: 0.654): Lateral Movement & Privilege Pivoting across internal network tiers.
  4. `DB01` (Step Cost: 1.36, Risk: 0.639): Crown Jewel Exfiltration Target holding mission-critical databases (Criticality 5/5).
* **Adversary Route Comparison**: The 3-hop breach corridor (`WEB01 ➔ APP01 ➔ DB01`, Cost 4.08) was selected over the 5-hop VPN route (`VPN01 ➔ EMP01 ➔ AUTH01 ➔ APP01 ➔ DB01`, Cost 6.85) due to lower defensive friction.

### 8. CSP Remediation Plan Output
```text
[8/8] Solving Constraint Satisfaction Problem (CSP) for Remediation...
      Remediation Solver: Backtracking CSP (Status: feasible)
      Pipeline Integration: Selected 5 high-impact tasks from 240 predictions
      Attack Path Alignment: Prioritized perimeter and intermediate targets on WEB01, APP01, DB01
      Pending Backlog: 235 vulnerabilities queued for subsequent scheduling cycles
      Generated Feasible Patch Schedule:
        - Mon 09:00: Web Team -> V0036 (Critical on WEB01)
        - Mon 09:00: Database Team -> V0128 (Critical on DB01)
        - Mon 09:00: Network Team -> V0186 (Critical on VPN01)
        - Mon 14:00: Application Team -> V0426 (Critical on APP01) [Prerequisite: V0036]
        - Mon 14:00: Database Team -> V0040 (Critical on BACKUP01) [Prerequisite: V0128]
      Saved: artifacts/csp/patch_schedule.json
```
* **Meaning**: The Backtracking CSP solver produces a verified, feasible patch schedule from the 240 test predictions:
  - **Attack-Path Prioritization**: Flaws on active corridor hosts (`WEB01`, `APP01`, `DB01`) are scheduled first to break the attack path.
  - **Defense-in-Depth Breadth**: Adjacent hosts (`VPN01`, `BACKUP01`) are incorporated to engage all specialized teams.
  - **Constraint Enforcement**: Strictly zero team concurrency conflicts (max 1 task per team per slot) and prerequisite orderings enforced (`APP01` remediation requires prior `WEB01` boundary mitigation; `BACKUP01` requires prior `DB01` database mitigation).
  - **Backlog Management**: The remaining 235 non-critical/deferred flaws are tracked in a pending backlog queue for subsequent cycles.

### 9. Structured Explainability Output
```text
Explainability Sample:
  Predicted risk for V1136 on DB01: Critical. Primary driver: Exploitability (Attack Ease) (Exploitability=0.91, Impact=0.83).
```
* **Meaning**: Transforms opaque predictions into defensible, human-verifiable security evidence:
  - **Feature Attribution**: Deconstructs raw CVSS metrics into normalized Exploitability ($AC, PR, UI, EP$) and CIA Impact ($CI, II, AI$) subscores, identifying the dominant risk driver.
  - **Asset Context**: Incorporates host criticality (`Level 5/5 Crown Jewel`) and exposure scope (`Internal Network`) from `network.json`.
  - **Evidence-Based Factors**: Generates bulleted justifications (e.g., Unauthenticated Access $PR=0$, Autonomous Exploitation $UI=0$, Weaponization Probability $\ge 60\%$).
  - **Actionable Guidance**: Recommends targeted operational steps (e.g., emergency patch deployment within 24h, firewall segmentation).

### 10. What-If Scenario Simulation Output
```text
Simulating patch impact on WEB01 (-50% risk reduction)...
  Baseline Risk: 0.634 -> Simulated Risk: 0.317 (-0.317)
  Adversary Traversal Cost: 4.08 -> 4.39 (+0.31 Defensive Gain)
  Attack Path Status: Maintained (Hardened)
```
* **Meaning**: Simulates applying security remediation to target systems on an isolated copy of the network state without severing topology connectivity, recomputing risk-aware A* attack paths to quantitatively measure defensive gain.

---

## E. Faculty Presentation Walkthrough

This section provides a structured 5–7 minute demonstration covering both the **Data + ML Foundation** and **Week 2 Heuristic Search, CSP Remediation & Explainability** deliverables.

### 1. 5–7 Minute Demonstration Sequence

| Step & Time | Focus Area | Action / Command | What to Show Ma'am | Artifact / File Location |
| :--- | :--- | :--- | :--- | :--- |
| **Step 1** (1 min) | **Dataset Integrity & Balance** | `.venv\Scripts\python.exe -c "import pandas as pd; df=pd.read_csv('data/raw/vulnerabilities.csv', keep_default_na=False); print(df.shape); print(df['risk_label'].value_counts())"` | Show 1,200 records, exactly 300 per class (Low, Medium, High, Critical), 0 missing values, and all 7 target enterprise host systems (out of 8 network topology nodes). | `data/raw/vulnerabilities.csv`<br>`docs/DATA_SCHEMA.md` |
| **Step 2** (1 min) | **Preprocessing & Feature Engineering** | `.venv\Scripts\python.exe -c "import pandas as pd; df=pd.read_csv('data/processed/vulnerabilities_processed.csv'); print(df.head(3))"` | Show how 6 categorical attributes are mapped to ordinal numbers (0, 1, 2) alongside continuous `exploit_probability` (0.0-1.0), while `vuln_id` and `system_id` are preserved and `description` dropped. Highlight zero target leakage. | `src/preprocessing.py`<br>`data/processed/vulnerabilities_processed.csv` |
| **Step 3** (1.5 min) | **K-Means Cluster Analysis** | `.venv\Scripts\python.exe src/kmeans_clustering.py` | 1. Open `artifacts/kmeans/elbow_plot.png` showing the inertia elbow at $K=4$ ($D^2=189.30$).<br>2. Open `artifacts/kmeans/silhouette_plot.png` (explaining modest 0.14-0.18 scores from discrete ordinal space).<br>3. Open `artifacts/kmeans/cluster_analysis.txt` to explain the 4 measured vulnerability profiles based on User Interaction (None vs. Required) and Exploitability/Impact levels. | `artifacts/kmeans/elbow_plot.png`<br>`artifacts/kmeans/cluster_profiles.csv`<br>`artifacts/kmeans/cluster_analysis.txt` |
| **Step 4** (1.5 min) | **KNN Model Training & Evaluation** | `.venv\Scripts\python.exe src/knn_classifier.py` | 1. Show 5-Fold Cross-Validation table selecting $K=3$ (CV Acc: 72.81%).<br>2. Open `artifacts/knn/confusion_matrix.png`.<br>3. Review `artifacts/knn/evaluation_report.txt` showing held-out test accuracy of 73.75%, precision 0.7288, recall 0.7375, F1 0.7298. | `artifacts/knn/k_selection_cv.csv`<br>`artifacts/knn/confusion_matrix.png`<br>`artifacts/knn/evaluation_report.txt` |
| **Step 5** (1 min) | **A* Search, CSP & Explainability** | `.venv\Scripts\python.exe main.py` | 1. Show A* critical path output (`INTERNET -> WEB01 -> APP01 -> DB01`, Cost: 4.08).<br>2. Show CSP patch schedule (5 tasks scheduled, 235 pending in backlog).<br>3. Show Explainability sample deconstructing Exploitability vs. Impact. | `artifacts/astar/attack_path.json`<br>`artifacts/csp/patch_schedule.json` |
| **Step 6** (1 min) | **Automated Test Verification** | `.venv\Scripts\python.exe -m unittest discover -v -s tests -p "test_*.py"` | Show that all **88 automated unit and integration tests** pass with zero errors across all 8 test suites. | `tests/` |

### 2. Standalone Fallback Procedure (If GUI / Web Server is Unavailable)
If Streamlit or a browser cannot be launched during the viva, all artifacts are pre-generated, static, and inspectable:
* Open `artifacts/kmeans/elbow_plot.png` and `artifacts/knn/confusion_matrix.png` in Windows Photos.
* Open `artifacts/kmeans/cluster_analysis.txt` and `artifacts/knn/evaluation_report.txt` in Notepad / VS Code.
* Inspect `artifacts/astar/attack_path.json` and `artifacts/csp/patch_schedule.json`.
* Show the automated test output in the terminal (`Ran 88 tests in 4.8s - OK`).

---

## F. Bangla Presentation Script (With English Technical Terms)

> *"আসসালামু আলাইকুম ম্যাম। আজ আমরা TraceWard প্রজেক্টের সম্পূর্ণ ইন্টিগ্রেটেড সিস্টেম উপস্থাপন করছি।*
>
> ***১. Dataset & Preprocessing:***  
> *আমাদের vulnerability dataset সম্পূর্ণ প্রস্তুত। এতে মোট ১,২০০টি synthetic vulnerability record রয়েছে, যা চারটি risk class-এ (Low, Medium, High, Critical) সুষমভাবে ৩০০টি করে বিভক্ত। ৬টি categorical feature-কে ordinally encode করা হয়েছে এবং ১টি continuous numeric feature (`exploit_probability`) সহ মোট ৭টি সিকিউরিটি ডাইমেনশন প্রস্তুত করা হয়েছে। এখানে কোনো missing value নেই এবং identifiers (`vuln_id`, `system_id`) আলাদা রাখা হয়েছে যাতে কোনো target leakage না ঘটে।*
>
> ***২. K-Means Clustering ও Structural Profiling:***  
> *আমরা K-Means অ্যালগরিদম সফলভাবে বাস্তবায়ন করেছি এবং candidate K = 2 থেকে 8 পর্যন্ত পরীক্ষা করেছি। Inertia curve-এর discrete centered second difference elbow heuristic ($D^2=189.30$) এবং Silhouette Analysis বিশ্লেষণ করে আমরা $K=4$ নির্বাচন করেছি। এই ক্লাস্টারগুলো ভালনারেবিলিটির কাঠামোগত বৈশিষ্ট্য (structural profiles) প্রকাশ করে—যেমন automated exploitability বনাম user interaction requirements।*
>
> ***৩. KNN Risk Classification ও Model Selection:***  
> *সুপারভাইজড লার্নিংয়ের জন্য আমরা KNN ক্লাসিফায়ার তৈরি করেছি। ডেটাসেটকে ৮০/২০ অনুপাতে stratified split করা হয়েছে (৯৬০টি train, ২৪০টি test)। ডেটা লিকেজ সম্পূর্ণ রোধ করতে আমরা scikit-learn Pipeline ব্যবহার করে প্রতিটি CV fold-এর ভেতরে স্কেলার ফিট করেছি। Training set-এর ওপর 5-Fold Cross-Validation চালিয়ে $K=3$ নির্বাচিত হয়েছে (CV Acc: ৭২.৮১%)। ২৪০টি unseen held-out test ডেটায় মডেলটি ৭৩.৭৫% accuracy এবং ০.৭২৯৮ weighted F1-score অর্জন করেছে।*
>
> ***৪. A* Attack Path Detection ও Kill Chain:***  
> *আমরা নেটওয়ার্ক টপোলজি গ্রাফ তৈরি করেছি যেখানে এজ কস্ট ভালনারেবিলিটি রিস্কের ওপর নির্ভরশীল ($c(u,v) = \max(0.5, 2.0 - \text{Risk}(v))$)। A\* সার্চ অ্যালগরিদম untrusted INTERNET থেকে DB01 ডাটাবেস পর্যন্ত সর্বনিম্ন ফ্র্রিকশনের ক্রিটিক্যাল করিডোর (`WEB01 ➔ APP01 ➔ DB01`, Cost 4.08) সফলভাবে শনাক্ত করেছে, যা ৫-হপের অল্টারনেটিভ VPN রুট (Cost 6.85) থেকে অনেক বেশি ঝুঁকিপূর্ণ।*
>
> ***৫. CSP Remediation ও Explainability:***  
> *Backtracking CSP সলভার ব্যবহার করে আমরা টিম স্পেশালাইজেশন, ক্যাপাসিটি এবং ডিফেন্সিভ ডিপেনডেন্সি (Perimeter fixes before Internal fixes) বজায় রেখে ফিজিবল প্যাচ শিডিউল তৈরি করেছি। সাথে আমাদের Structured Explainability Engine প্রতিটি সিদ্ধান্তের পেছনে Exploitability বনাম Impact সাবস্কোর এবং স্পষ্ট ব্যাখ্যা প্রদান করে।*
>
> ***৬. Test Verification:***  
> *আমাদের সিস্টেমের সমস্ত **৮৮টি স্বয়ংক্রিয় ইউনিট এবং ইন্টিগ্রেশন টেস্ট (৮৮/৮৮ টেস্ট)** সম্পূর্ণ সফলভাবে পাস করেছে। ধন্যবাদ ম্যাম।"*

---

## G. Top 8 Viva Questions & Answers

#### Q1: Why did you select K = 4 clusters for K-Means? Did you just match the 4 risk labels?
**Answer**:  
*"No, Ma'am. We strictly avoided forcing K=4 based on risk labels because clustering is unsupervised and must discover feature structure, not replicate labels. In our candidate evaluation ($K=2..8$), we computed the discrete centered second difference of inertia, $C(k) = I(k-1) - 2 \cdot I(k) + I(k+1)$, across interior candidates $k \in [3, 7]$. At $K=4$, $C(4) = 189.30$, which marks the maximum deceleration in inertia reduction (compared to $C(3)=135.31$, $C(5)=39.81$, $C(6)=133.55$, $C(7)=-192.76$). This is a discrete elbow heuristic, not mathematical proof of a unique optimal count. Across all evaluated K, Silhouette scores show modest cluster separation (0.1465 to 0.1781) because 6 of 7 features are discrete ordinals; $K=4$ was retained under the elbow heuristic to balance variance reduction against model complexity."*

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

#### Q6: How does the A* algorithm model adversarial traversal friction, and why was WEB01 chosen over VPN01?
**Answer**:  
*"The edge traversal cost is dynamically computed as $c(u, v) = \max(0.5, \text{round}(2.0 - \text{Risk}(v), 2))$, where $\text{Risk}(v)$ is the destination host's normalized vulnerability score. Higher vulnerability lowers the traversal cost, modeling the path of least resistance. The 3-hop corridor `INTERNET ➔ WEB01 ➔ APP01 ➔ DB01` has total cost 4.08 ($1.37 + 1.35 + 1.36$), whereas the 5-hop VPN route `INTERNET ➔ VPN01 ➔ EMP01 ➔ AUTH01 ➔ APP01 ➔ DB01` has total cost 6.85. The A* algorithm with an admissible heuristic selected the WEB01 corridor as the critical threat path because it presents significantly lower defensive friction to the crown jewel."*

#### Q7: How does the CSP solver prevent scheduling conflicts and enforce defensive dependency ordering?
**Answer**:  
*"The solver formulates remediation as a Constraint Satisfaction Problem resolved via Backtracking Search. It enforces three strict constraints: (1) Team Qualification—each task is mapped to its authoritative team (Web, Application, Database, Network); (2) Capacity Limit—no team can handle more than 1 task in the same slot (zero multitasking); (3) Defensive Dependency Ordering—boundary perimeter fixes must be executed strictly prior to internal application fixes (`APP01` depends on `WEB01`, `BACKUP01` depends on `DB01`). If constraints conflict or resources are overconstrained, the solver flags an infeasible status rather than outputting an invalid schedule."*

#### Q8: How does the Explainability engine deconstruct predictions into Exploitability and CIA Impact subscores?
**Answer**:  
*"The explainability engine separates the 7 CVSS dimensions into two distinct subscores: Exploitability (weighted composite of Attack Complexity, Privileges Required, User Interaction, and Exploit Probability) and Impact (mean normalized Confidentiality, Integrity, and Availability impact). It compares these to identify the dominant risk driver, extracts host criticality and exposure scope from `network.json`, and outputs evidence-based justifications and actionable operational guidance."*

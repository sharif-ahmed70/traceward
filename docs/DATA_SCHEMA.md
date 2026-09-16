# TraceWard Data Schema

This document serves as the single source of truth for the vulnerability dataset used across the TraceWard project.

> **Note on Initial Dataset**: The initial sample dataset (`data/raw/vulnerabilities.csv`) is provided strictly for development, pipeline validation, and integration testing across team modules. It is **NOT** the final training dataset.

---

## Raw Vulnerability Dataset

- **File Path**: `data/raw/vulnerabilities.csv`
- **File Format**: Standard Comma-Separated Values (CSV), encoded in UTF-8.

### Column Specifications

| # | Column Name | Data Type | Allowed Values / Range | Description | Example |
|---|---|---|---|---|---|
| 1 | `vuln_id` | String | Unique string identifier | Unique identifier for the vulnerability record. | `V001` |
| 2 | `system_id` | String | Must match a valid node ID in `data/network/network.json` | The target system hosting or affected by the vulnerability. | `WEB01` |
| 3 | `attack_complexity` | Categorical | `Low`, `High` | The level of effort or conditions required to exploit the vulnerability. | `Low` |
| 4 | `privileges_required` | Categorical | `None`, `Low`, `High` | Level of privileges the attacker must possess prior to exploiting. | `None` |
| 5 | `user_interaction` | Categorical | `None`, `Required` | Whether a legitimate user must participate for an exploit to succeed. | `None` |
| 6 | `confidentiality_impact`| Categorical | `None`, `Low`, `High` | Impact on data privacy and confidentiality if exploited. | `High` |
| 7 | `integrity_impact` | Categorical | `None`, `Low`, `High` | Impact on data accuracy and modification if exploited. | `High` |
| 8 | `availability_impact` | Categorical | `None`, `Low`, `High` | Impact on service availability and uptime if exploited. | `High` |
| 9 | `exploit_probability` | Float | `0.0` to `1.0` (inclusive) | Estimated probability of exploitation. Higher value means more likely. | `0.85` |
| 10 | `risk_label` | Categorical | `Low`, `Medium`, `High`, `Critical` | Ground-truth risk classification label for evaluation and supervised learning. | `Critical` |
| 11 | `description` | String | Free-text string | Short, human-readable summary of the vulnerability. | `Public web service allows remote code execution` |

---

## Data Integrity Rules

1. **Naming Conventions**: Column headers must always remain strictly lowercase with underscores (`snake_case`).
2. **Standard Risk Labels**: `risk_label` capitalization must strictly use: `Low`, `Medium`, `High`, `Critical`.
3. **No Missing Value Placeholders**: Missing values must not be represented using arbitrary text such as `"-"`, `"unknown"`, or `"N/A"`. All values in the raw dataset must be present and valid.
4. **Uniqueness**: Each `vuln_id` must be unique within the dataset.
5. **System Reference**: Every `system_id` must correspond to an active system defined in `data/network/network.json`.
6. **Encoding**: Files must be stored with UTF-8 character encoding without BOM.
7. **Valid Category 'None'**: Note that `'None'` is a valid domain value for privileges and impacts (meaning no impact or no privileges). When reading with Pandas, use `pd.read_csv(filepath, keep_default_na=False)` so that `'None'` is retained as a category string rather than parsed as `NaN`.

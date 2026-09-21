"""TraceWard Streamlit Dashboard — Cybersecurity Decision Support."""

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

# ---------------------------------------------------------------------------
# Repository root & path setup
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "dashboard"))

from main import get_foundation_status  # noqa: E402
from src.risk_engine import RISK_SCORE_MAP, summarize_system_risk  # noqa: E402
from ui import (  # noqa: E402
    empty_state,
    info_card,
    inject_dark_theme,
    metric_card,
    metric_row,
    page_header,
    render_risk_explanation,
    render_sidebar,
    risk_badge,
    risk_legend,
    section_header,
    setup_page,
    status_indicator,
    technical_details,
    warning_card,
    chart_explainer,
)

# ---------------------------------------------------------------------------
# Artifact / data paths
# ---------------------------------------------------------------------------
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
DATA_DIR = REPO_ROOT / "data"

PREDICTIONS_PATH = ARTIFACTS_DIR / "knn" / "predictions.csv"
EVALUATION_REPORT_PATH = ARTIFACTS_DIR / "knn" / "evaluation_report.txt"
K_COMPARISON_IMG_PATH = ARTIFACTS_DIR / "knn" / "k_comparison.png"
KMEANS_CLUSTERS_PATH = ARTIFACTS_DIR / "kmeans" / "cluster_assignments.csv"
ASTAR_PATH = ARTIFACTS_DIR / "astar" / "attack_path.json"
CSP_PATH = ARTIFACTS_DIR / "csp" / "patch_schedule.json"
NETWORK_PATH = DATA_DIR / "network" / "network.json"
PROCESSED_DATA_PATH = DATA_DIR / "processed" / "vulnerabilities_processed.csv"
RAW_DATA_PATH = DATA_DIR / "raw" / "vulnerabilities.csv"

RISK_LABELS = ["Low", "Medium", "High", "Critical"]

# ---------------------------------------------------------------------------
# Page bootstrap
# ---------------------------------------------------------------------------
setup_page()
page = render_sidebar()

# ---------------------------------------------------------------------------
# Cached data loaders
# ---------------------------------------------------------------------------
@st.cache_data
def load_foundation_status():
    return get_foundation_status()


@st.cache_data
def load_csv_safe(path: Path):
    if path.exists():
        return pd.read_csv(path, keep_default_na=False)
    return None


@st.cache_data
def load_json_safe(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


foundation = load_foundation_status()
predictions_df = load_csv_safe(PREDICTIONS_PATH)
processed_df = load_csv_safe(PROCESSED_DATA_PATH)
network_data = load_json_safe(NETWORK_PATH)


# ---------------------------------------------------------------------------
# Utility: KNN metrics from predictions dataframe
# ---------------------------------------------------------------------------
def compute_knn_metrics(df: pd.DataFrame):
    if df.empty:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "confusion_matrix": None,
            "labels": RISK_LABELS,
        }
    y_true = df["actual_risk"]
    y_pred = df["predicted_risk"]
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, average="weighted", zero_division=0),
        "recall": recall_score(y_true, y_pred, average="weighted", zero_division=0),
        "f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=RISK_LABELS),
        "labels": RISK_LABELS,
    }


# ---------------------------------------------------------------------------
# PAGE: Overview
# ---------------------------------------------------------------------------
if page == "Overview":
    page_header("TraceWard", "Cyber Risk Command Center")
    st.caption(
        "TraceWard analyzes vulnerability data to identify risk levels, "
        "highlight the systems that need attention, and help plan remediation."
    )

    # ------------------------------------------------------------------
    # Real data ingestion
    # ------------------------------------------------------------------
    raw_df = load_csv_safe(RAW_DATA_PATH)
    predictions_df_local = load_csv_safe(PREDICTIONS_PATH)

    # Raw portfolio facts
    total_vulnerabilities = int(len(raw_df)) if raw_df is not None else None
    risk_distribution = raw_df["risk_label"].value_counts().to_dict() if raw_df is not None else {}
    affected_systems = sorted(raw_df["system_id"].unique().tolist()) if raw_df is not None else []
    affected_system_count = len(affected_systems)

    # Prediction-derived facts
    pred_critical = 0
    pred_high = 0
    system_summary = None
    if predictions_df_local is not None:
        pred_critical = int((predictions_df_local["predicted_risk"] == "Critical").sum())
        pred_high = int((predictions_df_local["predicted_risk"] == "High").sum())
        system_summary = summarize_system_risk(predictions_df_local)

    # Overall security status
    if predictions_df_local is not None and len(predictions_df_local) > 0:
        critical_share = pred_critical / len(predictions_df_local)
        if critical_share > 0.25:
            overall_status = "Critical Attention Required"
            status_explanation = (
                f"{critical_share:.0%} of analyzed vulnerabilities are classified as Critical. "
                "Immediate patching and containment are recommended."
            )
        elif pred_critical > 0 or pred_high > 0:
            overall_status = "Elevated Risk Detected"
            status_explanation = (
                f"{pred_critical} Critical and {pred_high} High-risk vulnerabilities were identified. "
                "Prioritize remediation for the highest-risk systems below."
            )
        else:
            overall_status = "No Critical Risks Detected"
            status_explanation = (
                "Current predictions show no Critical vulnerabilities. "
                "Continue monitoring and regular patching cycles."
            )
    else:
        overall_status = "Analysis Pending"
        status_explanation = (
            "Run the KNN pipeline to generate vulnerability risk predictions "
            "and populate the security overview."
        )

    info_card(overall_status, status_explanation)

    section_header("What We're Tracking", divider=True)

    # Compute available critical/high from raw if predictions are missing
    if predictions_df_local is None and raw_df is not None:
        pred_critical = int((raw_df["risk_label"] == "Critical").sum())
        pred_high = int((raw_df["risk_label"] == "High").sum())

    metric_row([
        {
            "label": "Total Vulnerabilities",
            "value": f"{total_vulnerabilities:,}" if total_vulnerabilities is not None else "—",
            "delta": f"{affected_system_count} systems" if affected_system_count else None,
        },
        {
            "label": "Critical Vulnerabilities",
            "value": str(pred_critical) if predictions_df_local is not None else f"{risk_distribution.get('Critical', 0):,} (raw)",
            "delta": "Requires immediate action" if pred_critical else "None detected",
        },
        {
            "label": "High-Risk Vulnerabilities",
            "value": str(pred_high) if predictions_df_local is not None else f"{risk_distribution.get('High', 0):,} (raw)",
            "delta": "Schedule soon" if pred_high else "None detected",
        },
        {
            "label": "Affected Systems",
            "value": f"{affected_system_count} of 8",
        },
    ])

    section_header("How Risks Are Spread", divider=True)
    risk_legend()

    # Risk distribution chart
    if raw_df is not None:
        import matplotlib.pyplot as plt

        labels = ["Low", "Medium", "High", "Critical"]
        counts = [risk_distribution.get(label, 0) for label in labels]
        colors = ["#10b981", "#f59e0b", "#f97316", "#ef4444"]

        fig, ax = plt.subplots(figsize=(8, 4))
        bars = ax.bar(labels, counts, color=colors, width=0.6, edgecolor="#111827", linewidth=1.5)
        ax.set_ylabel("Vulnerability Count", color="#d1d5db")
        ax.set_ylim(0, max(counts) * 1.15)
        ax.tick_params(colors="#d1d5db")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color("#374151")
        ax.spines["bottom"].set_color("#374151")
        ax.set_facecolor("#111827")
        fig.patch.set_facecolor("#111827")

        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 10,
                str(count),
                ha="center",
                va="bottom",
                color="#f3f4f6",
                fontweight="bold",
                fontsize=11,
            )

        fig.tight_layout()
        st.pyplot(fig)
        plt.close(fig)
        chart_explainer(
            "This chart shows how vulnerabilities are distributed across Low, Medium, High, and Critical risk levels. "
            "More Critical or High bars means more urgent attention is needed."
        )
    else:
        empty_state("📊", "No Data Available", "Load the raw vulnerability dataset to view risk distribution.")

    section_header("Systems That Need Attention", divider=True)

    if system_summary is not None and len(system_summary) > 0:
        top_systems = system_summary.head(5)

        for _, row in top_systems.iterrows():
            with st.container():
                cols = st.columns([3, 1, 1, 1, 2])
                with cols[0]:
                    st.markdown(f"**{row['system_id']}**")
                with cols[1]:
                    st.markdown(risk_badge(row["highest_risk"], size="medium"), unsafe_allow_html=True)
                with cols[2]:
                    st.metric("Vulnerabilities", int(row["vulnerability_count"]), label_visibility="collapsed")
                with cols[3]:
                    st.metric("Critical", int(row["critical_count"]), label_visibility="collapsed")
                with cols[4]:
                    st.metric(
                        "Risk Score",
                        f"{row['normalized_risk']:.2f}",
                        help="Risk severity from 0.25 to 1.0",
                        label_visibility="collapsed",
                    )
                st.markdown('<hr style="margin: 0.25rem 0 0.75rem 0;">', unsafe_allow_html=True)
        chart_explainer(
            "Systems are ordered by overall risk score. Higher scores mean more severe vulnerabilities. "
            "Use the Systems page to inspect each system in detail."
        )
    else:
        empty_state(
            "🔍",
            "No System Risk Data Yet",
            "Run the KNN pipeline and risk engine to see which systems need the most attention.",
        )

    section_header("What To Do First", divider=True)

    if system_summary is not None and len(system_summary) > 0:
        critical_systems = system_summary[system_summary["critical_count"] > 0]
        if len(critical_systems) > 0:
            worst = critical_systems.iloc[0]
            st.markdown(
                f"**Top Priority:** System **{worst['system_id']}** has "
                f"**{int(worst['critical_count'])} Critical** vulnerabilities with a risk score of "
                f"**{worst['normalized_risk']:.3f}**. This system should be patched immediately."
            )

            if len(critical_systems) > 1:
                st.markdown(
                    f"**Additional Attention:** {len(critical_systems) - 1} more system(s) contain Critical vulnerabilities. "
                    "Review the table above and schedule remediation in order of risk score."
                )
        else:
            st.markdown(
                "No systems currently contain Critical vulnerabilities. Continue monitoring and maintain regular security hygiene."
            )
    else:
        st.caption("Run the risk analysis pipeline to generate priority recommendations.")

    section_header("Where To Go Next", divider=True)

    if predictions_df_local is not None:
        info_card(
            "1. Review individual vulnerabilities",
            "Go to Risk Analysis to inspect each vulnerability's predicted risk level and the factors that contributed to it.",
        )
        info_card(
            "2. Inspect the network map",
            "Go to Security Map to see how systems are connected and identify potential risk paths.",
        )
        info_card(
            "3. Plan patching",
            "Go to Remediation Plan to see prioritized patching recommendations and schedules.",
        )
    else:
        info_card(
            "Run the risk analysis",
            "Execute the supervised classification workflow to generate vulnerability risk predictions. "
            "This will populate the Risk Analysis, Security Map, and Remediation Plan sections.",
        )

    with st.expander("How TraceWard Works"):
        st.markdown(
            """
            TraceWard analyzes your vulnerability data through four stages:

            1. **Data Preparation** — Raw vulnerability records are cleaned and encoded into a format suitable for analysis.
            2. **Risk Prediction** — A classification model predicts the risk level (Low, Medium, High, Critical) for each vulnerability.
            3. **Security Analysis** — Vulnerabilities are grouped by system, connections between systems are mapped, and overall risk is aggregated.
            4. **Recommended Action** — A scheduling tool creates a practical patching plan that respects team capacity and maintenance windows.

            The dashboard presents these results in plain language so you can make informed decisions without needing to understand the underlying algorithms.
            """
        )

# ---------------------------------------------------------------------------
# PAGE: Systems
# ---------------------------------------------------------------------------
elif page == "Systems":
    page_header("Systems", "System-level risk overview and which systems need attention")

    if predictions_df is None:
        warning_card(
            "Predictions File Missing",
            "The file `artifacts/knn/predictions.csv` was not found. Run the KNN pipeline before viewing system risk.",
        )
        st.stop()

    # Build system summary using existing risk_engine function
    system_summary = summarize_system_risk(predictions_df)

    # Friendly system name mapping from network data
    system_names = {}
    if network_data:
        for node in network_data.get("nodes", []):
            system_names[node["id"]] = node.get("name", node["id"])

    # ------------------------------------------------------------------
    # Visual system-risk list
    # ------------------------------------------------------------------
    section_header("Systems At Risk", divider=True)

    for _, row in system_summary.iterrows():
        system_id = row["system_id"]
        friendly_name = system_names.get(system_id, system_id)

        with st.container():
            cols = st.columns([3, 1, 1, 1, 2])
            with cols[0]:
                st.markdown(f"**{friendly_name}**")
                st.caption(f"`{system_id}`")
            with cols[1]:
                st.markdown(risk_badge(row["highest_risk"], size="medium"), unsafe_allow_html=True)
            with cols[2]:
                st.metric("Vulnerabilities", int(row["vulnerability_count"]), label_visibility="collapsed")
            with cols[3]:
                st.metric("Critical", int(row["critical_count"]), label_visibility="collapsed")
                with cols[4]:
                    st.metric(
                        "Risk Score",
                        f"{row['normalized_risk']:.2f}",
                        help="Risk severity from 0.25 to 1.0",
                        label_visibility="collapsed",
                    )
            st.markdown('<hr style="margin: 0.25rem 0 0.75rem 0;">', unsafe_allow_html=True)

    # ------------------------------------------------------------------
    # System selector and detail view
    # ------------------------------------------------------------------
    section_header("System Details", divider=True)

    available_systems = system_summary["system_id"].tolist()
    system_display_options = [
        f"{system_names.get(sid, sid)} ({sid})" for sid in available_systems
    ]
    system_display_to_id = dict(zip(system_display_options, available_systems))

    selected_display = st.selectbox("Select a system to inspect", system_display_options)
    selected_system = system_display_to_id[selected_display]

    system_row = system_summary[system_summary["system_id"] == selected_system].iloc[0]
    system_vulns = predictions_df[predictions_df["system_id"] == selected_system]

    # Load enriched data for technical details
    processed_local = load_csv_safe(PROCESSED_DATA_PATH)
    enriched = system_vulns.copy()
    if processed_local is not None:
        enriched = enriched.merge(
            processed_local[[
                "vuln_id",
                "attack_complexity",
                "privileges_required",
                "user_interaction",
                "confidentiality_impact",
                "integrity_impact",
                "availability_impact",
                "exploit_probability",
            ]],
            on="vuln_id",
            how="left",
        )

    # 1. Risk summary
    st.subheader("System Snapshot")
    summary_cols = st.columns(5)
    with summary_cols[0]:
        metric_card("System", friendly_name)
    with summary_cols[1]:
        metric_card("Highest Risk", risk_badge(system_row["highest_risk"], size="large"), unsafe_html=True)
    with summary_cols[2]:
        metric_card("Vulnerabilities", int(system_row["vulnerability_count"]))
    with summary_cols[3]:
        metric_card("Critical", int(system_row["critical_count"]))
    with summary_cols[4]:
        metric_card("High or Critical", int(system_row["high_or_critical_count"]))

    # 2. Vulnerabilities table
    st.subheader("Vulnerabilities On This System")
    vuln_display = enriched[[
        "vuln_id", "system_id", "predicted_risk", "actual_risk",
        "attack_complexity", "privileges_required", "user_interaction",
        "confidentiality_impact", "integrity_impact", "availability_impact",
        "exploit_probability",
    ]].copy()
    vuln_display.columns = [
        "Vulnerability", "Affected System", "Predicted Risk", "Actual Risk",
        "Attack Complexity", "Privileges Required", "User Interaction",
        "Confidentiality Impact", "Integrity Impact", "Availability Impact",
        "Exploit Probability",
    ]
    st.dataframe(vuln_display, width="stretch", hide_index=True)

    # 3. Risk distribution
    st.subheader("Risk Breakdown")
    risk_legend()
    risk_counts = system_vulns["predicted_risk"].value_counts().to_dict()
    risk_labels = ["Low", "Medium", "High", "Critical"]
    risk_values = [risk_counts.get(label, 0) for label in risk_labels]
    colors = ["#10b981", "#f59e0b", "#f97316", "#ef4444"]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(risk_labels, risk_values, color=colors, width=0.6, edgecolor="#111827", linewidth=1.5)
    ax.set_ylabel("Count", color="#d1d5db")
    ax.set_ylim(0, max(risk_values) * 1.2 if risk_values else 1)
    ax.tick_params(colors="#d1d5db")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#374151")
    ax.spines["bottom"].set_color("#374151")
    ax.set_facecolor("#111827")
    fig.patch.set_facecolor("#111827")
    for bar, val in zip(bars, risk_values):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + 0.1,
            str(val),
            ha="center", va="bottom", color="#f3f4f6", fontweight="bold", fontsize=11,
        )
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)

    # 4. Technical details
    with st.expander("Technical Details"):
        tech_summary = pd.DataFrame([{
            "system_id": system_row["system_id"],
            "vulnerability_count": int(system_row["vulnerability_count"]),
            "highest_risk": system_row["highest_risk"],
            "average_risk_score": round(float(system_row["average_risk_score"]), 3),
            "normalized_risk": round(float(system_row["normalized_risk"]), 3),
            "critical_count": int(system_row["critical_count"]),
            "high_or_critical_count": int(system_row["high_or_critical_count"]),
        }])
        st.dataframe(tech_summary, width="stretch", hide_index=True)
        st.markdown("**Raw vulnerability records:**")
        st.dataframe(enriched, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# PAGE: Risk Analysis
# ---------------------------------------------------------------------------
elif page == "Risk Analysis":
    page_header("Risk Analysis", "Vulnerability risk analysis and confidence assessment")

    if predictions_df is None:
        warning_card(
            "Risk Analysis Not Available",
            "The vulnerability risk predictions have not been generated yet. Run the KNN pipeline to enable this page.",
        )
        st.stop()

    # Load enriched data for details view
    processed_local = load_csv_safe(PROCESSED_DATA_PATH)
    enriched = predictions_df.copy()
    if processed_local is not None:
        enriched = enriched.merge(
            processed_local[[
                "vuln_id",
                "attack_complexity",
                "privileges_required",
                "user_interaction",
                "confidentiality_impact",
                "integrity_impact",
                "availability_impact",
                "exploit_probability",
            ]],
            on="vuln_id",
            how="left",
        )

    # Friendly column rename for display
    friendly_cols = {
        "vuln_id": "Vulnerability",
        "system_id": "Affected System",
        "predicted_risk": "Predicted Risk",
        "actual_risk": "Actual Risk",
    }
    display_df = enriched[[c for c in friendly_cols.keys() if c in enriched.columns]].rename(
        columns=friendly_cols
    )

    # Risk distribution counts from predictions
    risk_counts = predictions_df["predicted_risk"].value_counts().to_dict()
    risk_labels = ["Low", "Medium", "High", "Critical"]
    risk_values = [risk_counts.get(label, 0) for label in risk_labels]

    # SECTION 1 — Risk Breakdown
    section_header("Risk Breakdown", divider=True)
    risk_legend()

    dist_col1, dist_col2 = st.columns([3, 2])
    with dist_col1:
        import matplotlib.pyplot as plt

        colors = ["#10b981", "#f59e0b", "#f97316", "#ef4444"]
        fig, ax = plt.subplots(figsize=(7, 4))
        bars = ax.bar(risk_labels, risk_values, color=colors, width=0.6, edgecolor="#111827", linewidth=1.5)
        ax.set_ylabel("Vulnerability Count", color="#d1d5db")
        ax.set_ylim(0, max(risk_values) * 1.2 if risk_values else 1)
        ax.tick_params(colors="#d1d5db")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color("#374151")
        ax.spines["bottom"].set_color("#374151")
        ax.set_facecolor("#111827")
        fig.patch.set_facecolor("#111827")
        for bar, val in zip(bars, risk_values):
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                bar.get_height() + 1,
                str(val),
                ha="center", va="bottom", color="#f3f4f6", fontweight="bold", fontsize=11,
            )
        fig.tight_layout()
        st.pyplot(fig)
        plt.close(fig)
        chart_explainer(
            "This chart shows the number of vulnerabilities at each risk level. "
            "More Critical or High bars indicate more urgent attention is needed."
        )

    with dist_col2:
        st.markdown("<p style='color:#9ca3af; font-size:0.9rem; margin-bottom:0.5rem;'>Summary</p>", unsafe_allow_html=True)
        for label, value in zip(risk_labels, risk_values):
            st.markdown(
                f"<div style='display:flex; align-items:center; justify-content:space-between; padding:0.35rem 0; border-bottom:1px solid #1f2937;'>"
                f"<span style='color:#d1d5db;'>{label}</span>"
                f"<span style='font-weight:700; color:#f3f4f6;'>{value:,}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
        total = sum(risk_values)
        st.markdown(
            f"<div style='display:flex; align-items:center; justify-content:space-between; padding:0.5rem 0; margin-top:0.25rem;'>"
            f"<span style='color:#9ca3af; font-weight:600;'>Total Analyzed</span>"
            f"<span style='font-weight:700; color:#f3f4f6;'>{total:,}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    # SECTION 2 & 3 — Vulnerability Risk Table with Filtering
    section_header("All Analyzed Vulnerabilities", divider=True)

    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        risk_options = ["All"] + risk_labels
        selected_risk = st.selectbox("Show only risks of type...", risk_options, index=0)
    with filter_col2:
        system_options = ["All"] + sorted(predictions_df["system_id"].unique().tolist())
        selected_system = st.selectbox("Show only system...", system_options, index=0)

    filtered = display_df.copy()
    if selected_risk != "All":
        filtered = filtered[filtered["Predicted Risk"] == selected_risk]
    if selected_system != "All":
        filtered = filtered[filtered["Affected System"] == selected_system]

    st.caption(f"Showing {len(filtered):,} of {len(display_df):,} vulnerabilities")

    if len(filtered) == 0:
        empty_state("🔎", "No matching vulnerabilities", "Try adjusting the filters above.")
    else:
        st.dataframe(
            filtered,
            column_config={
                "Predicted Risk": st.column_config.TextColumn("Predicted Risk", width="small"),
                "Actual Risk": st.column_config.TextColumn("Actual Risk", width="small"),
            },
            width="stretch",
            hide_index=True,
        )

    # SECTION 4 — Vulnerability Details
    section_header("Vulnerability Details", divider=True)

    if len(filtered) == 0:
        empty_state("📋", "No vulnerabilities to display", "Adjust filters to select a vulnerability.")
    else:
        detail_options = (
            filtered["Vulnerability"] + " — " + filtered["Affected System"] + " (" + filtered["Predicted Risk"] + ")"
        ).tolist()
        selected_detail = st.selectbox("Select a vulnerability to inspect", detail_options)
        selected_vuln_id = selected_detail.split(" — ")[0]

        row = enriched[enriched["vuln_id"] == selected_vuln_id].iloc[0]

        render_risk_explanation(
            predicted_risk=row["predicted_risk"],
            affected_system=row["system_id"],
            vuln_id=row["vuln_id"],
            characteristics={
                "attack_complexity": row.get("attack_complexity"),
                "privileges_required": row.get("privileges_required"),
                "user_interaction": row.get("user_interaction"),
                "confidentiality_impact": row.get("confidentiality_impact"),
                "integrity_impact": row.get("integrity_impact"),
                "availability_impact": row.get("availability_impact"),
                "exploit_probability": row.get("exploit_probability"),
                "description": row.get("description"),
            },
        )

    # SECTION 5 — Analysis Accuracy
    section_header("Analysis Accuracy", divider=True)

    # Parse evaluation report for Selected K
    selected_k = "—"
    if EVALUATION_REPORT_PATH.exists():
        report_text = EVALUATION_REPORT_PATH.read_text(encoding="utf-8")
        for line in report_text.splitlines():
            if line.startswith("Selected K:"):
                selected_k = line.split(":", 1)[1].strip()
                break

    metrics = compute_knn_metrics(predictions_df)

    metric_row([
        {"label": "Accuracy", "value": f"{metrics['accuracy']:.2%}"},
        {"label": "Precision", "value": f"{metrics['precision']:.2%}"},
        {"label": "Recall", "value": f"{metrics['recall']:.2%}"},
        {"label": "F1 Score", "value": f"{metrics['f1']:.2%}"},
        {"label": "Selected K", "value": str(selected_k)},
    ])

    info_card(
        "How to read these results",
        "Accuracy: how often the prediction matched the known risk category. "
        "Precision: of all vulnerabilities flagged as a given risk level, how many were correct. "
        "Recall: of all vulnerabilities that truly had a given risk level, how many did the analysis find. "
        "F1 Score: a balanced measure combining precision and recall. "
        "Selected K: the number of similar historical cases used to make each prediction.",
    )

    # Confusion matrix
    st.subheader("Prediction Accuracy Matrix")
    cm = metrics["confusion_matrix"]
    if cm is not None:
        labels = metrics["labels"]
        fig, ax = plt.subplots(figsize=(6, 5))
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels)
        ax.set_yticklabels(labels)
        ax.set_xlabel("Predicted Risk Level")
        ax.set_ylabel("Actual Risk Level")
        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(
                    j, i, cm[i, j],
                    ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black",
                )
        fig.tight_layout()
        st.pyplot(fig)
        plt.close(fig)
        chart_explainer(
            "Rows show the actual risk level. Columns show what the analysis predicted. "
            "Diagonal values are correct predictions; off-diagonal values are mismatches."
        )
    else:
        info_card("No Data Available", "Not enough data to compute a confusion matrix.")

    if K_COMPARISON_IMG_PATH.exists():
        section_header("Model Selection Chart", divider=True)
        st.image(str(K_COMPARISON_IMG_PATH), caption="Analysis Accuracy vs Model Setting")
        chart_explainer(
            "This chart shows how prediction accuracy changes with different model settings. "
            "Higher accuracy means the analysis is more reliable."
        )

# ---------------------------------------------------------------------------
# PAGE: Security Map
# ---------------------------------------------------------------------------
elif page == "Security Map":
    page_header("Security Map", "Network topology and potential risk paths")

    if network_data is None:
        st.error("Network topology file missing.")
        st.stop()

    nodes = network_data.get("nodes", [])
    edges = network_data.get("edges", [])

    G = nx.DiGraph()
    node_id_to_name = {}
    for node in nodes:
        G.add_node(node["id"], **node)
        node_id_to_name[node["id"]] = node.get("name", node["id"])

    for edge in edges:
        G.add_edge(edge["source"], edge["target"], base_cost=edge.get("base_cost", 1))

    attack_path = load_json_safe(ASTAR_PATH)

    # Build node risk mapping from predictions if available
    node_risk = {}
    if predictions_df is not None:
        for _, row in predictions_df.iterrows():
            sid = row["system_id"]
            risk = row["predicted_risk"]
            if sid not in node_risk:
                node_risk[sid] = {"count": 0, "max_risk": risk, "max_score": RISK_SCORE_MAP.get(risk, 0)}
            else:
                score = RISK_SCORE_MAP.get(risk, 0)
                if score > node_risk[sid]["max_score"]:
                    node_risk[sid]["max_risk"] = risk
                    node_risk[sid]["max_score"] = score
                node_risk[sid]["count"] += 1
    else:
        for node in nodes:
            node_risk[node["id"]] = None

    # ------------------------------------------------------------------
    # Layout and styling
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(14, 9))
    pos = nx.spring_layout(G, seed=42, k=1.2, iterations=100)

    # Node colors: risk-based if predictions available, else criticality-based
    node_colors = []
    node_border_colors = []
    for n in G.nodes():
        risk_info = node_risk.get(n)
        if risk_info and risk_info.get("max_risk"):
            risk = risk_info["max_risk"]
            if risk == "Critical":
                node_colors.append("#7f1d1d")
                node_border_colors.append("#ef4444")
            elif risk == "High":
                node_colors.append("#7c2d12")
                node_border_colors.append("#f97316")
            elif risk == "Medium":
                node_colors.append("#78350f")
                node_border_colors.append("#f59e0b")
            else:
                node_colors.append("#065f46")
                node_border_colors.append("#10b981")
        else:
            crit = G.nodes[n].get("criticality", 1)
            if crit >= 5:
                node_colors.append("#374151")
                node_border_colors.append("#9ca3af")
            elif crit >= 4:
                node_colors.append("#374151")
                node_border_colors.append("#9ca3af")
            else:
                node_colors.append("#1f2937")
                node_border_colors.append("#6b7280")

    # Draw edges
    nx.draw_networkx_edges(
        G, pos, ax=ax, edge_color="#4b5563", arrows=True,
        arrowsize=18, width=2.0, alpha=0.8,
        connectionstyle="arc3,rad=0.1",
    )

    # Draw nodes
    nx.draw_networkx_nodes(
        G, pos, ax=ax, node_color=node_colors, node_size=1200,
        edgecolors=node_border_colors, linewidths=2.5,
    )

    # Node labels with system ID and friendly name
    labels = {}
    for n in G.nodes():
        friendly = node_id_to_name.get(n, n)
        labels[n] = f"{n}\n({friendly})"
    nx.draw_networkx_labels(G, pos, ax=ax, labels=labels, font_size=9, font_weight="bold", font_color="#f3f4f6")

    # Highlight attack path if available
    if attack_path and "path" in attack_path:
        path = attack_path["path"]
        path_edges = list(zip(path, path[1:]))
        nx.draw_networkx_edges(
            G, pos, edgelist=path_edges, ax=ax,
            edge_color="#ef4444", width=4.5, arrows=True, arrowsize=22,
            connectionstyle="arc3,rad=0.1",
        )
        ax.set_title(
            "Network Topology — Critical Attack Path Highlighted",
            fontsize=15, fontweight="bold", color="#f3f4f6", pad=20,
        )
    else:
        ax.set_title("Network Topology", fontsize=15, fontweight="bold", color="#f3f4f6", pad=20)

    ax.axis("off")
    fig.patch.set_facecolor("#0b0f19")
    ax.set_facecolor("#0b0f19")
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)

    # ------------------------------------------------------------------
    # Legend / explanation
    # ------------------------------------------------------------------
    if attack_path and "path" in attack_path:
        path = attack_path["path"]
        path_length = len(path)
        st.markdown(
            f"**Potential route identified through {path_length - 1} connected systems.** "
            f"This path moves from external entry points toward a critical internal asset. "
            f"Each hop represents a network connection that could be exploited if vulnerabilities exist."
        )
    else:
        st.markdown(
            "**Risk path analysis integration is coming soon.** "
            "The map above shows the full network layout. "
            "Once the path analysis module is ready, the most concerning route will be highlighted here."
        )

    # ------------------------------------------------------------------
    # Path details or pending state
    # ------------------------------------------------------------------
    if attack_path and "path" in attack_path:
        section_header("Detected Attack Path", divider=True)
        path = attack_path["path"]
        for i, node_id in enumerate(path):
            friendly = node_id_to_name.get(node_id, node_id)
            risk_info = node_risk.get(node_id)
            risk_badge_html = ""
            if risk_info and risk_info.get("max_risk"):
                risk_badge_html = f' {risk_badge(risk_info["max_risk"], size="small")}'

            st.markdown(
                f"**{i + 1}.** `{node_id}` — {friendly}{risk_badge_html}",
                unsafe_allow_html=True,
            )
            if i < len(path) - 1:
                st.markdown("&nbsp;&nbsp;&nbsp;&nbsp;↓")

        st.markdown(f"**Total cost:** {attack_path.get('total_cost', 'N/A')}")
    else:
        section_header("Integration Status", divider=True)
        info_card(
            "Risk Path Analysis — Coming Soon",
            "The path analysis module has not yet been connected. "
            "When ready, it will identify the most critical route from external entry points to high-value internal systems. "
            "This map will then highlight that path and explain why it was selected.",
        )

    # ------------------------------------------------------------------
    # System directory with risk status
    # ------------------------------------------------------------------
    section_header("System Directory", divider=True)

    node_rows = []
    for n in nodes:
        risk_info = node_risk.get(n["id"])
        risk_display = risk_info["max_risk"] if risk_info and risk_info.get("max_risk") else "Not analyzed"
        node_rows.append({
            "Node ID": n["id"],
            "Name": n.get("name", ""),
            "Type": n.get("type", ""),
            "Criticality": n.get("criticality", 1),
            "Risk Status": risk_display,
            "Internet Exposed": "Yes" if n.get("internet_exposed") else "No",
        })
    st.dataframe(pd.DataFrame(node_rows), width="stretch", hide_index=True)

    # ------------------------------------------------------------------
    # Technical details
    # ------------------------------------------------------------------
    with st.expander("Technical Network Details"):
        st.markdown("**Nodes:**")
        st.json({n["id"]: {k: v for k, v in n.items() if k != "id"} for n in nodes})
        st.markdown("**Edges:**")
        edge_df = pd.DataFrame(edges)
        st.dataframe(edge_df, width="stretch", hide_index=True)
        if attack_path:
            st.markdown("**Attack Path Result:**")
            st.json(attack_path)
        else:
            st.caption("No attack path result available yet.")

# ---------------------------------------------------------------------------
# PAGE: Remediation Plan
# ---------------------------------------------------------------------------
elif page == "Remediation Plan":
    page_header("Remediation Plan", "Remediation planning and patching schedules")

    if predictions_df is None:
        warning_card(
            "Predictions Not Available",
            "Run the KNN pipeline first to generate risk predictions for remediation planning.",
        )
        st.stop()

    # Friendly system name mapping
    system_names = {}
    if network_data:
        for node in network_data.get("nodes", []):
            system_names[node["id"]] = node.get("name", node["id"])

    # Build system summary for priorities
    system_summary = summarize_system_risk(predictions_df)

    # ------------------------------------------------------------------
    # Section 1: Remediation Priorities
    # ------------------------------------------------------------------
    section_header("What Needs Patching First", divider=True)

    st.markdown(
        "These items are presented for remediation planning based on the available risk analysis. "
        "Priority is determined by the highest predicted risk level and the number of Critical vulnerabilities."
    )

    # Build priority list from actual risk data
    priority_rows = []
    for rank, (_, row) in enumerate(system_summary.iterrows(), start=1):
        system_id = row["system_id"]
        friendly_name = system_names.get(system_id, system_id)
        highest_risk = row["highest_risk"]

        if highest_risk == "Critical":
            action = "Immediate patching required"
        elif highest_risk == "High":
            action = "Schedule patching soon"
        elif highest_risk == "Medium":
            action = "Plan patching in next maintenance window"
        else:
            action = "Monitor and patch during regular maintenance"

        priority_rows.append({
            "Priority": rank,
            "Affected System": f"{friendly_name} ({system_id})",
            "Highest Risk": highest_risk,
            "Vulnerabilities": int(row["vulnerability_count"]),
            "Critical": int(row["critical_count"]),
            "Suggested Action": action,
            "Planning Status": "Pending review",
        })

    priority_df = pd.DataFrame(priority_rows)

    # Display with color-coded risk badges
    for _, row in priority_df.iterrows():
        with st.container():
            cols = st.columns([1, 3, 1, 1, 3, 2])
            with cols[0]:
                st.markdown(f"**#{row['Priority']}**")
            with cols[1]:
                st.markdown(f"**{row['Affected System']}**")
            with cols[2]:
                st.markdown(risk_badge(row["Highest Risk"], size="medium"), unsafe_allow_html=True)
            with cols[3]:
                st.metric("Vulns", row["Vulnerabilities"], label_visibility="collapsed")
            with cols[4]:
                st.caption(row["Suggested Action"])
            with cols[5]:
                st.markdown(f"<span style='color:#9ca3af; font-size:0.85rem;'>{row['Planning Status']}</span>", unsafe_allow_html=True)
            st.markdown('<hr style="margin: 0.25rem 0 0.75rem 0;">', unsafe_allow_html=True)

    # ------------------------------------------------------------------
    # Section 2: Feasible Remediation Schedule
    # ------------------------------------------------------------------
    section_header("Patching Schedule", divider=True)

    if CSP_PATH.exists():
        schedule = load_json_safe(CSP_PATH)
        if schedule:
            st.dataframe(pd.DataFrame(schedule), width="stretch", hide_index=True)
        else:
            warning_card("Patch Schedule Empty", "The CSP module produced an empty schedule.")
    else:
        empty_state(
            "📋",
            "Patching Schedule — Coming Soon",
            "The scheduling tool has not yet been connected. When ready, it will assign patching tasks to teams and maintenance windows while respecting operational constraints. "
            "This section will display the schedule once generated.",
        )

    # ------------------------------------------------------------------
    # Section 3: Technical Details
    # ------------------------------------------------------------------
    with st.expander("Technical Details"):
        st.markdown("**CSP Module Contract**")
        st.markdown(
            """
            The CSP solver (`src/csp_solver.py`) is expected to produce a schedule with the following structure:

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

            **Inputs:**
            - `artifacts/astar/attack_path.json` — Detected attack path
            - Vulnerability priorities / risk ratings
            - Available remediation teams
            - Maintenance time slots
            - Operational constraints

            **Current Status:** Module not yet implemented.
            """
        )

        st.markdown("**Current Artifact Status**")
        artifact_status = [
            {"Artifact": "Patch Schedule", "Path": "artifacts/csp/patch_schedule.json", "Exists": "Yes" if CSP_PATH.exists() else "No"},
            {"Artifact": "Attack Path", "Path": "artifacts/astar/attack_path.json", "Exists": "Yes" if ASTAR_PATH.exists() else "No"},
            {"Artifact": "KNN Predictions", "Path": "artifacts/knn/predictions.csv", "Exists": "Yes" if PREDICTIONS_PATH.exists() else "No"},
        ]
        st.dataframe(pd.DataFrame(artifact_status), width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# PAGE: What-If Analysis
# ---------------------------------------------------------------------------
elif page == "What-If Analysis":
    page_header("What-If Analysis", "Scenario planner for safe remediation simulation")

    if predictions_df is None:
        warning_card(
            "Predictions Not Available",
            "Run the KNN pipeline first to enable what-if simulations.",
        )
        st.stop()

    system_summary = summarize_system_risk(predictions_df)
    available_systems = sorted(predictions_df["system_id"].unique().tolist())

    # Friendly system name mapping
    system_names = {}
    if network_data:
        for node in network_data.get("nodes", []):
            system_names[node["id"]] = node.get("name", node["id"])

    selected_system = st.selectbox(
        "Select a system to simulate",
        available_systems,
        format_func=lambda sid: f"{system_names.get(sid, sid)} ({sid})",
    )

    system_preds = predictions_df[predictions_df["system_id"] == selected_system]
    system_row_df = system_summary[system_summary["system_id"] == selected_system]

    if len(system_row_df) == 0:
        st.error("Selected system not found in risk summary.")
        st.stop()

    system_row = system_row_df.iloc[0]

    # ------------------------------------------------------------------
    # CURRENT STATE
    # ------------------------------------------------------------------
    section_header("Current Situation", divider=True)

    st.caption("These values reflect the current risk analysis for the selected system.")

    current_cols = st.columns(4)
    with current_cols[0]:
        metric_card("Risk Level", risk_badge(system_row["highest_risk"], size="large"), unsafe_html=True)
    with current_cols[1]:
        metric_card("Vulnerability Count", int(system_row["vulnerability_count"]))
    with current_cols[2]:
        metric_card("Critical Vulnerabilities", int(system_row["critical_count"]))
    with current_cols[3]:
        metric_card("High or Critical", int(system_row["high_or_critical_count"]))

    st.markdown(
        f"**Normalized risk score:** {system_row['normalized_risk']:.3f} "
        f"(ranges from 0.25 to 1.0, where higher means greater risk severity)"
    )

    # ------------------------------------------------------------------
    # SIMULATED CHANGE
    # ------------------------------------------------------------------
    section_header("Try a Scenario", divider=True)

    st.caption("Choose a safe scenario to see how the portfolio risk would change.")

    scenario = st.radio(
        "Scenario",
        [
            "Patch all vulnerabilities in this system",
            "Patch only Critical vulnerabilities in this system",
        ],
        horizontal=True,
    )

    if scenario == "Patch all vulnerabilities in this system":
        scenario_description = (
            f"All {len(system_preds)} vulnerabilities in {selected_system} are marked as remediated."
        )
        remaining = predictions_df[predictions_df["system_id"] != selected_system]
        vulns_removed = len(system_preds)
    else:
        critical_vulns = system_preds[system_preds["predicted_risk"] == "Critical"]
        vuln_ids_to_remove = set(critical_vulns["vuln_id"].tolist())
        remaining = predictions_df[~predictions_df["vuln_id"].isin(vuln_ids_to_remove)]
        vulns_removed = len(vuln_ids_to_remove)
        scenario_description = (
            f"{vulns_removed} Critical vulnerabilities in {selected_system} are marked as remediated."
        )

    st.markdown(f"**Scenario:** {scenario_description}")

    if vulns_removed == 0:
        info_card(
            "No Vulnerabilities to Remove",
            "The selected scenario does not apply to this system because there are no matching vulnerabilities.",
        )
        st.stop()

    # ------------------------------------------------------------------
    # BEFORE vs AFTER
    # ------------------------------------------------------------------
    section_header("Compare Before and After", divider=True)

    overall_before = system_summary["normalized_risk"].mean()
    if len(remaining) > 0:
        new_summary = summarize_system_risk(remaining)
        overall_after = new_summary["normalized_risk"].mean()
        remaining_systems = len(new_summary)
    else:
        overall_after = 0.0
        remaining_systems = 0

    before_col, after_col = st.columns(2)

    with before_col:
        st.subheader("Before")
        st.markdown(f"**Systems analyzed:** {len(system_summary)}")
        st.markdown(f"**Total vulnerabilities:** {len(predictions_df)}")
        st.markdown(f"**Average portfolio risk score:** {overall_before:.3f}")

        st.markdown(
            f"**{selected_system}** — "
            f"{int(system_row['vulnerability_count'])} vulnerabilities, "
            f"highest risk: {system_row['highest_risk']}"
        )

    with after_col:
        st.subheader("After")
        st.markdown(f"**Remaining systems:** {remaining_systems}")
        st.markdown(f"**Remaining vulnerabilities:** {len(remaining)}")
        st.markdown(f"**Average portfolio risk score:** {overall_after:.3f}")

        if len(remaining) > 0:
            remaining_system_row = new_summary[new_summary["system_id"] == selected_system]
            if len(remaining_system_row) > 0:
                rs = remaining_system_row.iloc[0]
                st.markdown(
                    f"**{selected_system}** — "
                    f"{int(rs['vulnerability_count'])} vulnerabilities remaining, "
                    f"highest risk: {rs['highest_risk']}"
                )
            else:
                st.markdown(f"**{selected_system}** — no vulnerabilities remaining in portfolio")
        else:
            st.markdown(f"**{selected_system}** — all vulnerabilities removed from portfolio")

    # Delta metrics
    st.markdown("**Portfolio impact:**")
    impact_cols = st.columns(3)
    with impact_cols[0]:
        st.metric(
            "Vulnerabilities Removed",
            vulns_removed,
            delta=f"-{vulns_removed}",
            delta_color="inverse",
        )
    with impact_cols[1]:
        risk_delta = overall_after - overall_before
        st.metric(
            "Average Portfolio Risk Score",
            f"{overall_after:.3f}",
            delta=f"{risk_delta:+.3f}",
            delta_color="inverse" if risk_delta < 0 else "normal",
        )
    with impact_cols[2]:
        if len(remaining) > 0:
            new_critical = int(new_summary["critical_count"].sum())
            old_critical = int(system_summary["critical_count"].sum())
            st.metric(
                "Total Critical Vulnerabilities",
                new_critical,
                delta=f"{new_critical - old_critical:+d}",
                delta_color="inverse",
            )
        else:
            st.metric("Total Critical Vulnerabilities", 0, delta="—")

    # ------------------------------------------------------------------
    # Updated system risk summary
    # ------------------------------------------------------------------
    if len(remaining) > 0:
        section_header("Updated Risk Summary", divider=True)
        st.dataframe(new_summary, width="stretch", hide_index=True)

    # ------------------------------------------------------------------
    # Simulation disclaimer
    # ------------------------------------------------------------------
    st.markdown(
        """
        <div style="
            background-color: #111827;
            border: 1px solid #374151;
            border-left: 4px solid #6b7280;
            border-radius: 0.5rem;
            padding: 0.75rem 1rem;
            margin-top: 1rem;
        ">
            <div style="color: #9ca3af; font-size: 0.85rem;">
                <strong>Important: This Is a Simulation</strong><br>
                This is a simulated scenario based on removing vulnerabilities from the dataset and recalculating risk summaries. 
                It does not represent actual exploitation, scanning, or guarantee real-world risk reduction. 
                Simulation capability will become more accurate when the remediation/risk integration is connected.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ------------------------------------------------------------------
    # Technical Details
    # ------------------------------------------------------------------
    with st.expander("Technical Details"):
        st.markdown("**Simulation Parameters**")
        st.json({
            "selected_system": selected_system,
            "scenario": scenario,
            "vulnerabilities_removed": vulns_removed,
            "portfolio_avg_risk_before": round(float(overall_before), 3),
            "portfolio_avg_risk_after": round(float(overall_after), 3),
            "remaining_vulnerabilities": int(len(remaining)),
            "note": "After-state is computed by removing selected vulnerabilities from predictions and recalculating risk_engine.summarize_system_risk().",
        })

# ---------------------------------------------------------------------------
# PAGE: Technical Details
# ---------------------------------------------------------------------------
elif page == "Technical Details":
    page_header("Technical Details", "Low-level implementation information for developers and reviewers")

    technical_details(
        "Foundation Status",
        raw_records=foundation.get("raw_records"),
        processed_records=foundation.get("processed_records"),
        network_nodes=foundation.get("network_nodes"),
        network_edges=foundation.get("network_edges"),
    )

    technical_details(
        "Module Artifacts",
        artifacts={
            name: str((ARTIFACTS_DIR / rel).relative_to(REPO_ROOT))
            for name, rel in {
                "KNN Predictions": "knn/predictions.csv",
                "Evaluation Report": "knn/evaluation_report.txt",
                "K Comparison Chart": "knn/k_comparison.png",
                "K-Means Clusters": "kmeans/cluster_assignments.csv",
                "Attack Path": "astar/attack_path.json",
                "Patch Schedule": "csp/patch_schedule.json",
            }.items()
        },
        data_files={
            name: str((DATA_DIR / rel).relative_to(REPO_ROOT))
            for name, rel in {
                "Network Topology": "network/network.json",
                "Processed Data": "processed/vulnerabilities_processed.csv",
                "Raw Data": "raw/vulnerabilities.csv",
            }.items()
        },
    )

    if st.checkbox("Preview raw network JSON"):
        if network_data:
            st.json(network_data)

    st.subheader("Evaluation Report")
    if EVALUATION_REPORT_PATH.exists():
        report_text = EVALUATION_REPORT_PATH.read_text(encoding="utf-8")
        st.code(report_text, language="text")
    else:
        info_card("Evaluation Report Not Found", "Run the KNN pipeline to generate the evaluation report.")

    st.subheader("Data Schema")
    st.markdown(
        """
        **Vulnerability Dataset** uses 7 encoded security features:
        - `attack_complexity`, `privileges_required`, `user_interaction`
        - `confidentiality_impact`, `integrity_impact`, `availability_impact`
        - `exploit_probability` (float 0.0 – 1.0)

        Target: `risk_label` (Low, Medium, High, Critical)

        Identifiers (`vuln_id`, `system_id`) are preserved but excluded from the ML feature matrix.
        """
    )

    st.subheader("Module Contracts")
    st.markdown("See `docs/MODULE_CONTRACTS.md` for full interface specifications.")

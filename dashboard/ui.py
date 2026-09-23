"""Reusable UI/design layer for the TraceWard Streamlit dashboard."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st


# ---------------------------------------------------------------------------
# Theme / page configuration
# ---------------------------------------------------------------------------
def setup_page() -> None:
    """Configure the Streamlit page with a dark cybersecurity command-center theme."""
    st.set_page_config(
        page_title="TraceWard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_dark_theme()


def inject_dark_theme() -> None:
    """Inject custom CSS for a dark, high-contrast cybersecurity aesthetic."""
    st.markdown(
        """
        <style>
        :root {
            --tw-bg-base: #0b0f19;
            --tw-bg-surface: #111827;
            --tw-bg-elevated: #1f2937;
            --tw-border: #374151;
            --tw-text-primary: #f3f4f6;
            --tw-text-secondary: #9ca3af;
            --tw-accent: #3b82f6;
            --tw-risk-low: #10b981;
            --tw-risk-medium: #f59e0b;
            --tw-risk-high: #f97316;
            --tw-risk-critical: #ef4444;
        }

        * {
            box-sizing: border-box;
        }

        body {
            background-color: var(--tw-bg-base);
            color: var(--tw-text-primary);
        }

        .stApp {
            background-color: var(--tw-bg-base);
        }

        .main .block-container {
            padding-top: 2.5rem;
            padding-bottom: 3rem;
            max-width: 1400px;
        }

        h1, h2, h3, h4, h5, h6 {
            color: var(--tw-text-primary) !important;
            font-weight: 600;
            letter-spacing: -0.02em;
        }

        .stMetric {
            background-color: var(--tw-bg-surface);
            border: 1px solid var(--tw-border);
            border-radius: 0.75rem;
            padding: 1rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }

        .stMetric label {
            color: var(--tw-text-secondary) !important;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .stMetric [data-testid="stMetricValue"] {
            color: var(--tw-text-primary) !important;
            font-size: 1.75rem;
            font-weight: 700;
        }

        .stDataFrame {
            background-color: var(--tw-bg-surface);
            border: 1px solid var(--tw-border);
            border-radius: 0.5rem;
        }

        .stTabs [data-baseweb="tab-list"] {
            background-color: var(--tw-bg-surface);
            border-radius: 0.5rem;
            padding: 0.25rem;
            gap: 0.25rem;
        }

        .stTabs [data-baseweb="tab"] {
            color: var(--tw-text-secondary) !important;
            border-radius: 0.375rem;
            padding: 0.5rem 1rem;
            font-weight: 500;
        }

        .stTabs [aria-selected="true"] {
            background-color: var(--tw-bg-elevated);
            color: var(--tw-text-primary) !important;
        }

        .stButton>button {
            background-color: var(--tw-bg-elevated);
            color: var(--tw-text-primary);
            border: 1px solid var(--tw-border);
            border-radius: 0.5rem;
            font-weight: 500;
        }

        .stButton>button:hover {
            background-color: #374151;
            border-color: #4b5563;
        }

        .stSelectbox label,
        .stCheckbox label {
            color: var(--tw-text-primary) !important;
            font-weight: 500;
        }

        .stInfo, .stWarning, .stError, .stSuccess {
            border-radius: 0.5rem;
            border: 1px solid var(--tw-border);
        }

        code {
            background-color: var(--tw-bg-elevated);
            padding: 0.2rem 0.4rem;
            border-radius: 0.25rem;
            font-size: 0.9em;
        }

        pre {
            background-color: var(--tw-bg-elevated);
            border: 1px solid var(--tw-border);
            border-radius: 0.5rem;
            padding: 1rem;
            overflow-x: auto;
        }

        hr {
            border-color: var(--tw-border);
            margin: 1.5rem 0;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def render_sidebar() -> str:
    """Render the TraceWard sidebar and return the selected page name."""
    with st.sidebar:
        st.markdown(
            """
            <div style="padding: 0.5rem 0; margin-bottom: 0.5rem;">
                <span style="font-size: 1.5rem;">🛡️</span>
                <span style="font-size: 1.1rem; font-weight: 700; color: #f3f4f6; margin-left: 0.5rem;">TraceWard</span>
            </div>
            <p style="color: #9ca3af; font-size: 0.8rem; margin: 0 0 1rem 0.25rem;">
                Cyber Risk Analysis & Attack Path Detection
            </p>
            """,
            unsafe_allow_html=True,
        )
        st.markdown('<hr style="margin: 0.5rem 0 1rem 0;">', unsafe_allow_html=True)

        page = st.radio(
            "Navigation",
            [
                "Overview",
                "Systems",
                "Risk Analysis",
                "Security Map",
                "Remediation Plan",
                "What-If Analysis",
                "Technical Details",
            ],
            label_visibility="collapsed",
        )

        st.markdown(
            '<hr style="margin: 1rem 0 0.5rem 0;">', unsafe_allow_html=True
        )
        st.caption("TraceWard v0.1 — University AI Lab")
    return page


# ---------------------------------------------------------------------------
# Typography / layout helpers
# ---------------------------------------------------------------------------
def page_header(title: str, subtitle: str = "") -> None:
    """Render a consistent page title and optional subtitle."""
    st.markdown(f"<h1 style='margin-bottom: 0.25rem;'>{title}</h1>", unsafe_allow_html=True)
    if subtitle:
        st.markdown(
            f"<p style='color: #9ca3af; font-size: 1.05rem; margin-top: 0;'>{subtitle}</p>",
            unsafe_allow_html=True,
        )
    st.markdown('<hr style="margin: 1.25rem 0;">', unsafe_allow_html=True)


def section_header(title: str, divider: bool = True) -> None:
    """Render a section header with optional divider."""
    st.markdown(f"<h3 style='margin-top: 1.5rem; margin-bottom: 0.75rem;'>{title}</h3>", unsafe_allow_html=True)
    if divider:
        st.markdown('<hr style="margin: 0 0 1.25rem 0;">', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Metric cards
# ---------------------------------------------------------------------------
def metric_card(label: str, value: Any, delta: str | None = None, delta_color: str = "normal", unsafe_html: bool = False) -> None:
    """Display a single metric using Streamlit's native metric component.

    Args:
        label: Metric label.
        value: Metric value.
        delta: Optional delta string.
        delta_color: Delta color style.
        unsafe_html: If True, render value with st.markdown(..., unsafe_allow_html=True).
            Use only for trusted HTML strings such as risk badges.
    """
    if unsafe_html:
        st.markdown(
            f"<div style='margin-bottom: 0.5rem;'>"
            f"<span style='color: #9ca3af; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;'>{label}</span>"
            f"<div style='margin-top: 0.25rem;'>{value}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
    else:
        st.metric(label=label, value=value, delta=delta, delta_color=delta_color)


def metric_row(metrics: list[dict[str, Any]]) -> None:
    """Render a row of metric cards.

    Each dict should contain:
        - label (str)
        - value (Any)
        - delta (str, optional)
        - delta_color (str, optional)
    """
    cols = st.columns(len(metrics))
    for col, m in zip(cols, metrics):
        with col:
            metric_card(
                label=m.get("label", ""),
                value=m.get("value", "—"),
                delta=m.get("delta"),
                delta_color=m.get("delta_color", "normal"),
            )


# ---------------------------------------------------------------------------
# Risk badges
# ---------------------------------------------------------------------------
_RISK_COLORS = {
    "Low": {"bg": "#065f46", "text": "#6ee7b7", "border": "#10b981"},
    "Medium": {"bg": "#78350f", "text": "#fcd34d", "border": "#f59e0b"},
    "High": {"bg": "#7c2d12", "text": "#fdba74", "border": "#f97316"},
    "Critical": {"bg": "#7f1d1d", "text": "#fecaca", "border": "#ef4444"},
}


def risk_badge(label: str, size: str = "medium") -> str:
    """Return an HTML span styled as a risk badge.

    Args:
        label: One of Low, Medium, High, Critical.
        size: One of small, medium, large.

    Returns:
        HTML string safe for use with st.markdown(unsafe_allow_html=True).
    """
    colors = _RISK_COLORS.get(
        label,
        {"bg": "#1f2937", "text": "#f3f4f6", "border": "#374151"},
    )
    size_px = {"small": "0.7rem", "medium": "0.8rem", "large": "0.9rem"}.get(size, "0.8rem")
    pad_y = {"small": "0.2rem", "medium": "0.35rem", "large": "0.45rem"}.get(size, "0.35rem")
    pad_x = {"small": "0.5rem", "medium": "0.75rem", "large": "1rem"}.get(size, "0.75rem")

    return (
        '<span style="'
        f'display: inline-block;'
        f'background-color: {colors["bg"]};'
        f'color: {colors["text"]};'
        f'border: 1px solid {colors["border"]};'
        f'border-radius: 9999px;'
        f'padding: {pad_y} {pad_x};'
        f'font-size: {size_px};'
        f'font-weight: 600;'
        f'text-transform: uppercase;'
        f'letter-spacing: 0.04em;'
        f'white-space: nowrap;'
        f'">{label}</span>'
    )


# ---------------------------------------------------------------------------
# Status indicators
# ---------------------------------------------------------------------------
def status_indicator(status: str, label: str = "") -> None:
    """Render a small inline status dot with optional text label."""
    color_map = {
        "ready": "#10b981",
        "ok": "#10b981",
        "success": "#10b981",
        "missing": "#ef4444",
        "error": "#ef4444",
        "pending": "#f59e0b",
        "running": "#3b82f6",
        "info": "#3b82f6",
    }
    color = color_map.get(status.lower(), "#9ca3af")
    text = label or status.title()
    st.markdown(
        f"""
        <div style="display: flex; align-items: center; gap: 0.5rem; margin: 0.25rem 0;">
            <span style="
                display: inline-block;
                width: 0.6rem;
                height: 0.6rem;
                border-radius: 50%;
                background-color: {color};
                box-shadow: 0 0 6px {color};
            "></span>
            <span style="color: #d1d5db; font-size: 0.9rem;">{text}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Callout cards
# ---------------------------------------------------------------------------
def info_card(title: str, body: str) -> None:
    """Render an informational card with a title and body text."""
    st.markdown(
        f"""
        <div style="
            background-color: #111827;
            border: 1px solid #1e3a5f;
            border-left: 4px solid #3b82f6;
            border-radius: 0.5rem;
            padding: 1rem 1.25rem;
            margin: 0.75rem 0;
        ">
            <div style="color: #93c5fd; font-weight: 600; font-size: 0.95rem; margin-bottom: 0.35rem;">{title}</div>
            <div style="color: #d1d5db; font-size: 0.9rem; line-height: 1.5;">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def warning_card(title: str, body: str) -> None:
    """Render a warning card with a title and body text."""
    st.markdown(
        f"""
        <div style="
            background-color: #111827;
            border: 1px solid #5b3a1a;
            border-left: 4px solid #f59e0b;
            border-radius: 0.5rem;
            padding: 1rem 1.25rem;
            margin: 0.75rem 0;
        ">
            <div style="color: #fcd34d; font-weight: 600; font-size: 0.95rem; margin-bottom: 0.35rem;">{title}</div>
            <div style="color: #d1d5db; font-size: 0.9rem; line-height: 1.5;">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def empty_state(
    icon: str,
    title: str,
    body: str = "",
    action_label: str = "",
    action_callback: Any = None,
) -> None:
    """Render an empty / not-yet-available state with optional action button."""
    st.markdown(
        f"""
        <div style="
            text-align: center;
            padding: 3rem 1rem;
            color: #9ca3af;
        ">
            <div style="font-size: 3rem; margin-bottom: 1rem;">{icon}</div>
            <div style="font-size: 1.1rem; font-weight: 600; color: #d1d5db; margin-bottom: 0.5rem;">{title}</div>
            {f"<div style='font-size: 0.95rem; max-width: 32rem; margin: 0 auto; line-height: 1.5;'>{body}</div>" if body else ""}
        </div>
        """,
        unsafe_allow_html=True,
    )
    if action_label and action_callback:
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            st.button(action_label, on_click=action_callback, type="primary")


# ---------------------------------------------------------------------------
# Technical details expander
# ---------------------------------------------------------------------------
def technical_details(label: str = "Technical Details", **kwargs: Any) -> None:
    """Render an expandable section for low-level technical information."""
    with st.expander(label):
        if kwargs:
            st.json(kwargs)
        st.markdown(
            """
            <div style="color: #9ca3af; font-size: 0.85rem;">
                This section contains low-level implementation details for reviewers and developers.
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Loading / progress helpers
# ---------------------------------------------------------------------------
def loading_state(message: str = "Loading data…") -> None:
    """Show a spinner with a custom message and return the context manager."""
    return st.spinner(message)


def progress_bar(label: str, value: float, min_value: float = 0.0, max_value: float = 1.0) -> None:
    """Render a progress bar."""
    st.progress(value=value, min=min_value, max=max_value, text=label)


# ---------------------------------------------------------------------------
# Legend / explainer helpers
# ---------------------------------------------------------------------------
def risk_legend() -> None:
    """Display a compact legend for Low/Medium/High/Critical risk colors."""
    st.markdown(
        """
        <div style="display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; margin: 0.5rem 0;">
            <span style="display: inline-block; width: 0.75rem; height: 0.75rem; border-radius: 50%; background-color: #10b981;"></span>
            <span style="color: #d1d5db; font-size: 0.9rem;"><strong>Low</strong> — Minimal immediate risk</span>
            <span style="display: inline-block; width: 0.75rem; height: 0.75rem; border-radius: 50%; background-color: #f59e0b;"></span>
            <span style="color: #d1d5db; font-size: 0.9rem;"><strong>Medium</strong> — Moderate concern</span>
            <span style="display: inline-block; width: 0.75rem; height: 0.75rem; border-radius: 50%; background-color: #f97316;"></span>
            <span style="color: #d1d5db; font-size: 0.9rem;"><strong>High</strong> — Significant risk</span>
            <span style="display: inline-block; width: 0.75rem; height: 0.75rem; border-radius: 50%; background-color: #ef4444;"></span>
            <span style="color: #d1d5db; font-size: 0.9rem;"><strong>Critical</strong> — Immediate action required</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def chart_explainer(text: str) -> None:
    """Render a short plain-English caption below a chart."""
    st.caption(text)


# ---------------------------------------------------------------------------
# Explainability helpers
# ---------------------------------------------------------------------------
_ATTACK_COMPLEXITY_MAP = {
    0: "Low",
    1: "High",
}

_PRIVILEGES_REQUIRED_MAP = {
    0: "None",
    1: "Low",
    2: "High",
}

_USER_INTERACTION_MAP = {
    0: "None",
    1: "Required",
}

_IMPACT_MAP = {
    0: "None",
    1: "Low",
    2: "High",
}


def _decode_feature(value, mapping: dict[int, str]) -> str:
    """Safely map a numeric feature value to its human-readable label."""
    if pd.isna(value):
        return "Not specified"
    try:
        return mapping.get(int(value), str(value))
    except (ValueError, TypeError):
        return str(value)


def _build_characteristic_bullets(row: dict[str, Any]) -> list[str]:
    """Return a list of human-readable characteristic bullets from encoded features."""
    bullets = []

    complexity = _decode_feature(row.get("attack_complexity"), _ATTACK_COMPLEXITY_MAP)
    if complexity == "Low":
        bullets.append("Easy to exploit — low technical barriers")
    elif complexity == "High":
        bullets.append("Harder to exploit — requires specific conditions or tools")

    privileges = _decode_feature(row.get("privileges_required"), _PRIVILEGES_REQUIRED_MAP)
    if privileges == "None":
        bullets.append("No prior access needed — an unauthenticated attacker could exploit this")
    elif privileges == "Low":
        bullets.append("Requires limited access — attacker needs some initial foothold")
    elif privileges == "High":
        bullets.append("Requires elevated access — attacker must already have administrative rights")

    interaction = _decode_feature(row.get("user_interaction"), _USER_INTERACTION_MAP)
    if interaction == "None":
        bullets.append("No user action required — can be exploited automatically")
    elif interaction == "Required":
        bullets.append("Requires a user to take action — e.g., click a link or open a file")

    conf = _decode_feature(row.get("confidentiality_impact"), _IMPACT_MAP)
    if conf == "High":
        bullets.append("High data exposure risk — sensitive information could be accessed")
    elif conf == "Low":
        bullets.append("Limited data exposure — some information could be revealed")

    integrity = _decode_feature(row.get("integrity_impact"), _IMPACT_MAP)
    if integrity == "High":
        bullets.append("High data modification risk — attackers could alter data or code")
    elif integrity == "Low":
        bullets.append("Limited data modification risk — some data could be changed")

    availability = _decode_feature(row.get("availability_impact"), _IMPACT_MAP)
    if availability == "High":
        bullets.append("High service disruption risk — systems could go offline")
    elif availability == "Low":
        bullets.append("Limited service disruption — minor performance or availability impact")

    try:
        prob = float(row.get("exploit_probability", 0))
        if prob >= 0.7:
            bullets.append(f"High exploitation likelihood ({prob:.0%})")
        elif prob >= 0.4:
            bullets.append(f"Moderate exploitation likelihood ({prob:.0%})")
        else:
            bullets.append(f"Lower exploitation likelihood ({prob:.0%})")
    except (ValueError, TypeError):
        pass

    return bullets


def _build_plain_english_interpretation(
    predicted_risk: str,
    bullets: list[str],
) -> str:
    """Build an honest plain-English interpretation without overclaiming model causality."""
    risk_intro = {
        "Critical": "This vulnerability was classified as Critical, meaning it poses a severe threat to the system.",
        "High": "This vulnerability was classified as High, indicating a significant security concern.",
        "Medium": "This vulnerability was classified as Medium, suggesting a moderate risk that should be addressed.",
        "Low": "This vulnerability was classified as Low, indicating minimal immediate risk.",
    }
    base = risk_intro.get(
        predicted_risk,
        "TraceWard classified this vulnerability based on its security characteristics and similarity to previously evaluated vulnerabilities.",
    )

    if bullets:
        base += " The following characteristics contribute to this assessment:"
    else:
        base += " Detailed explanation is not available from the current model output."

    return base


def render_risk_explanation(
    predicted_risk: str,
    affected_system: str,
    vuln_id: str,
    characteristics: dict[str, Any] | None = None,
) -> None:
    """Render a human-readable explanation for a predicted risk level.

    Args:
        predicted_risk: One of Low, Medium, High, Critical.
        affected_system: The system ID where the vulnerability was found.
        vuln_id: The vulnerability identifier.
        characteristics: Optional dict of encoded feature values. Keys should match
            the processed dataset columns: attack_complexity, privileges_required,
            user_interaction, confidentiality_impact, integrity_impact,
            availability_impact, exploit_probability.
    """
    st.markdown("### Why This Risk?")
    st.markdown(
        f"**Risk Level:** {risk_badge(predicted_risk, size='large')}  "
        f"&nbsp;&nbsp; **Affected System:** `{affected_system}`  "
        f"&nbsp;&nbsp; **Vulnerability:** `{vuln_id}`",
        unsafe_allow_html=True,
    )

    characteristics = characteristics or {}
    bullets = _build_characteristic_bullets(characteristics)

    if bullets:
        st.markdown("**Key contributing characteristics:**")
        for bullet in bullets:
            st.markdown(f"- {bullet}")
    else:
        st.caption("No additional characteristic data is available for this vulnerability.")

    interpretation = _build_plain_english_interpretation(predicted_risk, bullets)
    info_card("Plain-English interpretation", interpretation)

    with st.expander("Technical Details"):
        if characteristics:
            tech_df = pd.DataFrame([{
                "vuln_id": vuln_id,
                "system_id": affected_system,
                "predicted_risk": predicted_risk,
                **{k: characteristics.get(k, "—") for k in [
                    "attack_complexity",
                    "privileges_required",
                    "user_interaction",
                    "confidentiality_impact",
                    "integrity_impact",
                    "availability_impact",
                    "exploit_probability",
                    "description",
                ]},
            }])
            st.dataframe(tech_df, width="stretch", hide_index=True)
        else:
            st.caption("No technical details available.")


def render_structured_explanation_card(exp: dict[str, Any]) -> None:
    """Render a clean, cybersecurity-themed structured explanation card."""
    risk_level = exp.get("predicted_risk", "Medium")
    subscores = exp.get("subscores", {})
    asset_ctx = exp.get("asset_context", {})
    factors = exp.get("risk_factors", [])
    action = exp.get("recommended_action", "")
    contributions = exp.get("feature_contributions", {})
    vote_share = exp.get("vote_share")

    st.markdown("#### Vulnerability Risk Explanation")

    # 1. Metric row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"<div style='margin-bottom: 0.5rem;'>"
            f"<span style='color: #9ca3af; font-size: 0.8rem; text-transform: uppercase;'>Predicted Risk</span>"
            f"<div style='margin-top: 0.25rem;'>{risk_badge(risk_level, size='medium')}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
    with c2:
        exp_score = subscores.get("exploitability_score", 0.0)
        c2.metric(
            "Exploitability",
            f"{exp_score * 100:.0f}%",
            help="Ease of attacker compromise based on complexity, authentication, and exploit availability.",
        )
    with c3:
        imp_score = subscores.get("impact_score", 0.0)
        c3.metric(
            "CIA Impact",
            f"{imp_score * 100:.0f}%",
            help="Severity of consequences across Confidentiality, Integrity, and Availability.",
        )
    with c4:
        driver = subscores.get("primary_driver", "N/A")
        driver_short = "Exploitability" if "Exploitability" in driver else "CIA Impact"
        c4.metric(
            "Primary Driver",
            driver_short,
            help="The dominant risk dimension driving this classification.",
        )

    if vote_share is not None:
        st.caption(f"KNN Neighbor Vote Share: **{vote_share * 100:.1f}%** nearest neighbors agree on {risk_level}.")

    # 2. Asset Context Box
    crit_label = asset_ctx.get("criticality_label", "Level 3/5")
    exp_scope = asset_ctx.get("exposure_scope", "Internal Network")
    st.markdown(
        f"<div style='background-color: #111827; border: 1px solid #374151; border-radius: 6px; padding: 0.75rem 1rem; margin: 0.75rem 0;'>"
        f"<span style='font-weight: 600; color: #f3f4f6;'>🛡️ Host Context: {asset_ctx.get('name', exp.get('system_id', 'Host'))}</span> "
        f"<span style='color: #9ca3af;'>({asset_ctx.get('type', 'Server')})</span> &nbsp;|&nbsp; "
        f"<span style='color: #f59e0b;'>{crit_label}</span> &nbsp;|&nbsp; "
        f"<span style='color: #3b82f6;'>{exp_scope}</span>"
        f"<p style='color: #9ca3af; font-size: 0.85rem; margin: 0.35rem 0 0 0;'>{asset_ctx.get('role_description', '')}</p>"
        f"</div>",
        unsafe_allow_html=True,
    )

    # 3. Evidence / Risk Factors
    if factors:
        st.markdown("**Key Risk Factors (Attribution Evidence):**")
        for factor in factors:
            st.markdown(f"- 🔍 {factor}")

    # 4. Actionable Remediation Guidance
    if action:
        st.info(f"**Recommended Action:** {action}")

    # 5. Technical Details Expander
    if contributions:
        with st.expander("Feature Contribution Breakdown (CVSS v3.1 Dimensions)"):
            rows = []
            for fname, fmeta in contributions.items():
                rows.append({
                    "Feature": fname.replace("_", " ").title(),
                    "Value": fmeta.get("display", str(fmeta.get("value", ""))),
                    "Normalized Risk": f"{fmeta.get('normalized_risk', 0.0):.2f}",
                    "Risk Impact": fmeta.get("direction", "Neutral"),
                    "Qualitative Rationale": fmeta.get("rationale", ""),
                })
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def render_remediation_priority_card(exp: dict[str, Any], task_row: dict[str, Any]) -> None:
    """Render an explainable card explaining why a remediation task received its priority and slot."""
    vuln_id = task_row.get("vuln_id", "")
    system_id = task_row.get("system_id", "")
    priority = task_row.get("priority", "High")
    team = task_row.get("team", "")
    time_slot = task_row.get("time_slot", "")
    deps = task_row.get("depends_on", [])

    st.markdown("#### Remediation Priority Rationale")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f"<div style='margin-bottom: 0.5rem;'>"
            f"<span style='color: #9ca3af; font-size: 0.8rem; text-transform: uppercase;'>Task Priority</span>"
            f"<div style='margin-top: 0.25rem;'>{risk_badge(priority, size='medium')}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
    with c2:
        c2.metric("Scheduled Slot", time_slot)
    with c3:
        c3.metric("Assigned Team", team)

    dep_text = (
        f"Prerequisite dependency on task(s): `{', '.join(deps)}`."
        if deps
        else "Zero prerequisite dependencies (can execute immediately in opening slot)."
    )

    path_systems = ["WEB01", "APP01", "DB01"]
    if system_id in path_systems:
        path_context = (
            f"**Critical Breach Corridor:** Host `{system_id}` is directly located on the primary adversary attack path "
            f"(`INTERNET -> WEB01 -> APP01 -> DB01`). Mitigating this flaw directly increases the attacker's traversal friction."
        )
    else:
        path_context = (
            f"**Defense-in-Depth:** Host `{system_id}` is an adjacent enterprise asset. "
            f"Mitigating this flaw protects against lateral perimeter pivoting."
        )

    st.markdown(
        f"<div style='background-color: #111827; border: 1px solid #374151; border-radius: 6px; padding: 0.75rem 1rem; margin: 0.75rem 0;'>"
        f"<p style='margin: 0 0 0.5rem 0; color: #f3f4f6;'><strong>Justification for {vuln_id} on {system_id}:</strong></p>"
        f"<p style='color: #9ca3af; font-size: 0.9rem; margin: 0 0 0.5rem 0;'>• {path_context}</p>"
        f"<p style='color: #9ca3af; font-size: 0.9rem; margin: 0;'>• <strong>Temporal Constraint:</strong> {dep_text}</p>"
        f"</div>",
        unsafe_allow_html=True,
    )



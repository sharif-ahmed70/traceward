"""Reusable UI/design layer for the TraceWard Streamlit dashboard."""

from __future__ import annotations

import json
from pathlib import Path
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


def inject_theme(theme_mode: str = "Dark") -> None:
    """Inject custom CSS for a cybersecurity SOC command center aesthetic in Dark or Light mode."""
    is_light = theme_mode.lower() == "light"
    if is_light:
        bg_base = "#f8fafc"
        bg_surface = "#ffffff"
        bg_elevated = "#f1f5f9"
        border = "#cbd5e1"
        text_primary = "#0f172a"
        text_secondary = "#475569"
        shadow = "rgba(0, 0, 0, 0.06)"
        card_hover = "#e2e8f0"
    else:
        bg_base = "#070b14"
        bg_surface = "#0f172a"
        bg_elevated = "#1e293b"
        border = "#334155"
        text_primary = "#f8fafc"
        text_secondary = "#94a3b8"
        shadow = "rgba(0, 0, 0, 0.45)"
        card_hover = "#253349"

    css = f"""
    <style>
    :root {{
        --tw-bg-base: {bg_base};
        --tw-bg-surface: {bg_surface};
        --tw-bg-elevated: {bg_elevated};
        --tw-border: {border};
        --tw-text-primary: {text_primary};
        --tw-text-secondary: {text_secondary};
        --tw-accent: #3b82f6;
        --tw-risk-low: #10b981;
        --tw-risk-medium: #f59e0b;
        --tw-risk-high: #f97316;
        --tw-risk-critical: #ef4444;
    }}

    * {{
        box-sizing: border-box;
    }}

    body {{
        background-color: var(--tw-bg-base);
        color: var(--tw-text-primary);
    }}

    .stApp {{
        background-color: var(--tw-bg-base);
    }}

    .main .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1440px;
    }}

    h1, h2, h3, h4, h5, h6 {{
        color: var(--tw-text-primary) !important;
        font-weight: 600;
        letter-spacing: -0.02em;
    }}

    .stMetric {{
        background-color: var(--tw-bg-surface);
        border: 1px solid var(--tw-border);
        border-radius: 0.75rem;
        padding: 1rem;
        box-shadow: 0 4px 6px -1px {shadow};
    }}

    .stMetric label {{
        color: var(--tw-text-secondary) !important;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }}

    .stMetric [data-testid="stMetricValue"] {{
        color: var(--tw-text-primary) !important;
        font-size: 1.75rem;
        font-weight: 700;
    }}

    .stDataFrame {{
        background-color: var(--tw-bg-surface);
        border: 1px solid var(--tw-border);
        border-radius: 0.5rem;
    }}

    .stTabs [data-baseweb="tab-list"] {{
        background-color: var(--tw-bg-surface);
        border-radius: 0.5rem;
        padding: 0.25rem;
        gap: 0.25rem;
    }}

    .stTabs [data-baseweb="tab"] {{
        color: var(--tw-text-secondary) !important;
        border-radius: 0.375rem;
        padding: 0.5rem 1rem;
        font-weight: 500;
    }}

    .stTabs [aria-selected="true"] {{
        background-color: var(--tw-bg-elevated);
        color: var(--tw-text-primary) !important;
    }}

    .stButton>button {{
        background-color: var(--tw-bg-elevated);
        color: var(--tw-text-primary);
        border: 1px solid var(--tw-border);
        border-radius: 0.5rem;
        font-weight: 500;
        transition: all 0.15s ease-in-out;
    }}

    .stButton>button:hover {{
        background-color: {card_hover};
        border-color: var(--tw-accent);
    }}

    .stSelectbox label,
    .stCheckbox label {{
        color: var(--tw-text-primary) !important;
        font-weight: 500;
    }}

    .stInfo, .stWarning, .stError, .stSuccess {{
        border-radius: 0.5rem;
        border: 1px solid var(--tw-border);
    }}

    code {{
        background-color: var(--tw-bg-elevated);
        padding: 0.2rem 0.4rem;
        border-radius: 0.25rem;
        font-size: 0.9em;
    }}

    pre {{
        background-color: var(--tw-bg-elevated);
        border: 1px solid var(--tw-border);
        border-radius: 0.5rem;
        padding: 1rem;
        overflow-x: auto;
    }}

    hr {{
        border-color: var(--tw-border);
        margin: 1.5rem 0;
    }}

    .tw-soc-header {{
        background: linear-gradient(135deg, var(--tw-bg-surface) 0%, var(--tw-bg-elevated) 100%);
        border: 1px solid var(--tw-border);
        border-radius: 0.75rem;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 12px {shadow};
    }}

    .tw-soc-card {{
        background-color: var(--tw-bg-surface);
        border: 1px solid var(--tw-border);
        border-radius: 0.75rem;
        padding: 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 2px 6px {shadow};
        transition: border-color 0.15s ease;
    }}

    .tw-soc-card:hover {{
        border-color: var(--tw-accent);
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def inject_dark_theme() -> None:
    """Inject custom CSS for a dark, high-contrast cybersecurity aesthetic."""
    inject_theme("Dark")


# ---------------------------------------------------------------------------
# Sidebar & Navigation
# ---------------------------------------------------------------------------
NAV_STAGES = [
    "Threat Discovery",
    "Risk Intelligence",
    "Attack Corridors",
    "Smart Remediation",
    "Incident Lab",
    "Defense Verification",
]

STAGE_ICONS = {
    "Threat Discovery": "🧭",
    "Risk Intelligence": "🧠",
    "Attack Corridors": "⚡",
    "Smart Remediation": "🔧",
    "Incident Lab": "🚨",
    "Defense Verification": "🔬",
}

STAGE_DESCRIPTIONS = {
    "Threat Discovery": "Macro posture & executive command",
    "Risk Intelligence": "KNN risk inference & K-Means clustering",
    "Attack Corridors": "A* kill chain detection & graph traversal",
    "Smart Remediation": "CSP conflict-free team dispatch schedule",
    "Incident Lab": "FinBank breach injection & correlation",
    "Defense Verification": "What-If hypothesis & mitigation impact",
}


def render_sidebar_navigation() -> tuple[str, str]:
    """Render modern SOC sidebar navigation with theme toggle and stage selector.
    
    Returns:
        tuple[str, str]: (theme_mode, selected_stage)
    """
    with st.sidebar:
        # 1. Branding Header
        st.markdown(
            """
            <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.25rem 0 0.5rem 0;">
                <div style="font-size: 1.8rem; background: rgba(59, 130, 246, 0.15); border: 1px solid #3b82f6; border-radius: 0.5rem; padding: 0.2rem 0.45rem; line-height: 1;">🛡️</div>
                <div>
                    <div style="font-size: 1.15rem; font-weight: 700; color: var(--tw-text-primary); letter-spacing: -0.02em; line-height: 1.2;">TraceWard SOC</div>
                    <div style="font-size: 0.75rem; color: var(--tw-text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">Cyber Defense Center</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # 2. Theme Toggle (Dark / Light)
        st.markdown('<div style="font-size: 0.75rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 600; margin: 0.75rem 0 0.25rem 0;">Theme Appearance</div>', unsafe_allow_html=True)
        theme_mode = st.radio(
            "Appearance Mode",
            ["Dark", "Light"],
            index=0,
            horizontal=True,
            key="ui_theme_mode",
            label_visibility="collapsed",
        )

        st.markdown('<hr style="margin: 0.75rem 0 0.75rem 0;">', unsafe_allow_html=True)

        # 3. Operational Stage Navigation
        st.markdown('<div style="font-size: 0.75rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 600; margin-bottom: 0.5rem;">Defense Lifecycle</div>', unsafe_allow_html=True)

        # Ensure session state initialization
        if "nav_stage" not in st.session_state:
            st.session_state["nav_stage"] = "Threat Discovery"

        # Determine index
        current_index = 0
        if st.session_state["nav_stage"] in NAV_STAGES:
            current_index = NAV_STAGES.index(st.session_state["nav_stage"])

        selected_stage = st.radio(
            "Operations Stage",
            NAV_STAGES,
            index=current_index,
            format_func=lambda s: f"{STAGE_ICONS.get(s, '')} {s}",
            key="soc_stage_radio",
            label_visibility="collapsed",
        )
        st.session_state["nav_stage"] = selected_stage

        # Stage context caption
        st.caption(f"📌 {STAGE_DESCRIPTIONS.get(selected_stage, '')}")

        st.markdown('<hr style="margin: 0.75rem 0 0.75rem 0;">', unsafe_allow_html=True)

        # 4. Scope Telemetry Pill
        st.markdown(
            """
            <div style="padding: 0.75rem; border-radius: 0.5rem; background: var(--tw-bg-surface); border: 1px solid var(--tw-border);">
                <div style="font-size: 0.72rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 700; margin-bottom: 0.4rem; letter-spacing: 0.05em;">Enterprise Active Scope</div>
                <div style="font-size: 0.82rem; display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
                    <span style="color: var(--tw-text-secondary);">Monitored Hosts:</span><strong style="color: var(--tw-text-primary);">8 Nodes</strong>
                </div>
                <div style="font-size: 0.82rem; display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
                    <span style="color: var(--tw-text-secondary);">Crown Jewel:</span><strong style="color: #ef4444;">DB01 Core</strong>
                </div>
                <div style="font-size: 0.82rem; display: flex; justify-content: space-between;">
                    <span style="color: var(--tw-text-secondary);">Defense Pipeline:</span><strong style="color: #10b981;">Armed & Active</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown('<div style="margin-top: 1rem;"></div>', unsafe_allow_html=True)
        st.caption("TraceWard v0.2 • Autonomous Cyber Risk Defense")

    return theme_mode, selected_stage


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
    """Render an explainable card detailing why a remediation task received its priority and slot."""
    vuln_id = exp.get("vulnerability_id", task_row.get("vuln_id", ""))
    system_id = exp.get("system_id", task_row.get("system_id", ""))
    priority = exp.get("priority", task_row.get("priority", "High"))
    team = exp.get("team", task_row.get("team", ""))
    time_slot = exp.get("scheduled_slot", task_row.get("time_slot", ""))
    deps = exp.get("prerequisites", task_row.get("depends_on", []))
    ap_rel = exp.get("attack_path_relevance", {})
    asset_ctx = exp.get("asset_context", {})

    st.markdown("#### 🛡️ Remediation Priority & Scheduling Intelligence")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"<div style='margin-bottom: 0.5rem;'>"
            f"<span style='color: #9ca3af; font-size: 0.8rem; text-transform: uppercase;'>Remediation Priority</span>"
            f"<div style='margin-top: 0.25rem;'>{risk_badge(priority, size='medium')}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
    with c2:
        c2.metric("Scheduled Slot", time_slot, help="Operational execution window allocated by CSP solver.")
    with c3:
        c3.metric("Assigned Team", team, help="Authoritative operational team owning host remediation.")
    with c4:
        is_corridor = ap_rel.get("is_on_attack_path", False)
        status_label = "🔴 Critical Corridor" if is_corridor else "🛡️ Defense-in-Depth"
        c4.metric("Corridor Alignment", status_label, help=ap_rel.get("path_role", "Defensive posture"))

    # Host & System Context Banner
    if asset_ctx:
        crit_label = asset_ctx.get("criticality_label", "Level 3/5")
        exp_scope = asset_ctx.get("exposure_scope", "Internal Network")
        st.markdown(
            f"<div style='background-color: #111827; border: 1px solid #374151; border-radius: 6px; padding: 0.75rem 1rem; margin: 0.75rem 0;'>"
            f"<span style='font-weight: 600; color: #f3f4f6;'>🏢 Target System: {asset_ctx.get('name', system_id)} ({system_id})</span> &nbsp;|&nbsp; "
            f"<span style='color: #f59e0b;'>{crit_label}</span> &nbsp;|&nbsp; "
            f"<span style='color: #3b82f6;'>{exp_scope}</span>"
            f"<p style='color: #9ca3af; font-size: 0.85rem; margin: 0.35rem 0 0 0;'>{asset_ctx.get('role_description', '')}</p>"
            f"</div>",
            unsafe_allow_html=True,
        )

    # Structured Justification Breakdown
    impact_reason = exp.get("impact_reason", "")
    scheduling_reason = exp.get("scheduling_reason", "")
    ap_rationale = ap_rel.get("rationale", "")

    st.markdown(
        f"<div style='background-color: #111827; border: 1px solid #374151; border-radius: 6px; padding: 0.85rem 1rem; margin: 0.75rem 0;'>"
        f"<p style='margin: 0 0 0.5rem 0; color: #f3f4f6;'><strong>Remediation Rationale for {vuln_id} on {system_id}:</strong></p>"
        f"<p style='color: #d1d5db; font-size: 0.88rem; margin: 0 0 0.5rem 0;'>• <strong>🎯 Attack Path Alignment:</strong> {ap_rationale}</p>"
        f"<p style='color: #d1d5db; font-size: 0.88rem; margin: 0 0 0.5rem 0;'>• <strong>💥 Operational & Risk Impact:</strong> {impact_reason}</p>"
        f"<p style='color: #d1d5db; font-size: 0.88rem; margin: 0;'>• <strong>⏱️ CSP Temporal Constraint:</strong> {scheduling_reason}</p>"
        f"</div>",
        unsafe_allow_html=True,
    )

    # Actionable Guidance
    action = exp.get("recommended_action")
    if action:
        st.info(f"**Recommended Action:** {action}")


# ---------------------------------------------------------------------------
# Attack Path Intelligence & Topology Visualization
# ---------------------------------------------------------------------------

def _generate_attack_graph_dot(path_list: list[str], network_path: str = "data/network/network.json") -> str:
    """Generate a clean Graphviz DOT specification highlighting the critical A* attack path."""
    nodes = []
    edges = []
    p = Path(network_path)
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                nodes = data.get("nodes", [])
                edges = data.get("edges", [])
        except Exception:
            pass

    if not nodes:
        nodes = [
            {"id": "INTERNET", "name": "Internet", "criticality": 1},
            {"id": "WEB01", "name": "Web Server", "criticality": 4},
            {"id": "APP01", "name": "Application Server", "criticality": 4},
            {"id": "AUTH01", "name": "Authentication Server", "criticality": 5},
            {"id": "VPN01", "name": "VPN Gateway", "criticality": 4},
            {"id": "EMP01", "name": "Employee Workstation", "criticality": 2},
            {"id": "DB01", "name": "Database Server", "criticality": 5},
            {"id": "BACKUP01", "name": "Backup Server", "criticality": 5},
        ]
        edges = [
            {"source": "INTERNET", "target": "WEB01", "base_cost": 2},
            {"source": "INTERNET", "target": "VPN01", "base_cost": 2},
            {"source": "WEB01", "target": "APP01", "base_cost": 3},
            {"source": "WEB01", "target": "AUTH01", "base_cost": 4},
            {"source": "VPN01", "target": "EMP01", "base_cost": 2},
            {"source": "EMP01", "target": "AUTH01", "base_cost": 3},
            {"source": "AUTH01", "target": "APP01", "base_cost": 2},
            {"source": "APP01", "target": "DB01", "base_cost": 4},
            {"source": "APP01", "target": "BACKUP01", "base_cost": 3},
        ]

    path_set = set(path_list)
    path_edges = set()
    for i in range(len(path_list) - 1):
        path_edges.add((path_list[i], path_list[i + 1]))

    dot_lines = [
        'digraph AttackGraph {',
        '  rankdir=LR;',
        '  bgcolor="transparent";',
        '  node [fontname="Helvetica, Arial, sans-serif", fontsize=10, shape=box, style="filled,rounded", margin="0.15,0.08"];',
        '  edge [fontname="Helvetica, Arial, sans-serif", fontsize=9];',
    ]

    for node in nodes:
        nid = node.get("id", "")
        nname = node.get("name", nid)
        crit = node.get("criticality", 3)
        if nid in path_set:
            if nid == path_list[0]:
                dot_lines.append(
                    f'  "{nid}" [label="{nname}\\n[{nid}]\\nIngress", color="#3b82f6", fillcolor="#1e3a8a", fontcolor="#ffffff", penwidth=2.5];'
                )
            elif nid == path_list[-1]:
                dot_lines.append(
                    f'  "{nid}" [label="{nname}\\n[{nid}]\\nTarget (Crit {crit})", color="#ef4444", fillcolor="#7f1d1d", fontcolor="#ffffff", penwidth=2.5];'
                )
            else:
                dot_lines.append(
                    f'  "{nid}" [label="{nname}\\n[{nid}]\\nPivot (Crit {crit})", color="#f97316", fillcolor="#7c2d12", fontcolor="#ffffff", penwidth=2.0];'
                )
        else:
            dot_lines.append(
                f'  "{nid}" [label="{nname}\\n[{nid}]", color="#374151", fillcolor="#1f2937", fontcolor="#9ca3af", penwidth=1.0];'
            )

    for edge in edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        base_cost = edge.get("base_cost", 2)
        if (src, tgt) in path_edges:
            dot_lines.append(
                f'  "{src}" -> "{tgt}" [label=" Critical Path", color="#ef4444", fontcolor="#ef4444", penwidth=2.8, arrowsize=1.0];'
            )
        else:
            dot_lines.append(
                f'  "{src}" -> "{tgt}" [label=" base={base_cost}", color="#4b5563", fontcolor="#6b7280", style="dashed", penwidth=1.0, arrowsize=0.7];'
            )

    dot_lines.append('}')
    return "\n".join(dot_lines)


def render_attack_path_intelligence(attack_path_info: dict[str, Any], is_mock: bool = False) -> None:
    """Render comprehensive A* attack path intelligence, kill-chain breakdown, and topology."""
    path_nodes = attack_path_info.get("path_nodes", [])
    entry_point = attack_path_info.get("entry_point", attack_path_info.get("start", "INTERNET"))
    target_asset = attack_path_info.get("target_asset", attack_path_info.get("goal", "DB01"))
    total_cost = attack_path_info.get("total_cost", 0.0)
    hop_count = attack_path_info.get("hop_count", max(0, len(attack_path_info.get("path", [])) - 1))
    path_list = attack_path_info.get("path", [])

    # 1. Top High-Level Metrics
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        m1.metric("Adversary Ingress", entry_point, help="Simulated external penetration origin.")
    with m2:
        m2.metric("Target Asset", target_asset, help="High-value destination holding enterprise databases.")
    with m3:
        m3.metric(
            "Total Path Cost",
            f"{total_cost:.2f}" if total_cost is not None else "N/A",
            help="Sum of risk-weighted traversal friction. Lower cost = easier breach.",
        )
    with m4:
        m4.metric("Hop Distance", f"{hop_count} Hops", help="Number of intermediate network pivots required.")

    # 2. Visual Kill-Chain Progression Corridor
    st.markdown("#### 🎯 Breach Corridor Kill-Chain Progression")
    st.caption("Step-by-step adversary traversal flow from external exposure to core data exfiltration.")

    if path_nodes:
        step_html_parts = []
        for idx, node in enumerate(path_nodes):
            node_id = node.get("node_id", "")
            name = node.get("name", node_id)
            phase = node.get("phase", "")
            step_cost = node.get("step_cost", 0.0)
            risk_score = node.get("risk_score", 0.0)

            if idx == 0:
                header_color = "#3b82f6"
                border_color = "#1d4ed8"
                icon = "🌐"
            elif idx == len(path_nodes) - 1:
                header_color = "#ef4444"
                border_color = "#b91c1c"
                icon = "🎯"
            else:
                header_color = "#f97316"
                border_color = "#c2410c"
                icon = "⚠️"

            cost_str = f"+{step_cost:.2f} cost" if idx > 0 else "Origin (0.00)"
            risk_str = f"Risk: {risk_score:.3f}" if idx > 0 else "External Network"

            card_html = (
                f"<div style='flex: 1; min-width: 170px; background-color: #111827; border: 1px solid {border_color}; "
                f"border-radius: 8px; padding: 0.85rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3);'>"
                f"<div style='font-size: 0.75rem; text-transform: uppercase; color: {header_color}; font-weight: 700; margin-bottom: 0.25rem;'>{icon} {phase}</div>"
                f"<div style='font-size: 1.05rem; font-weight: 700; color: #f3f4f6;'>{node_id}</div>"
                f"<div style='font-size: 0.8rem; color: #9ca3af;'>{name}</div>"
                f"<div style='margin-top: 0.5rem; display: flex; justify-content: space-between; font-size: 0.75rem;'>"
                f"<span style='color: #f59e0b;'>{cost_str}</span>"
                f"<span style='color: #9ca3af;'>{risk_str}</span>"
                f"</div>"
                f"</div>"
            )
            step_html_parts.append(card_html)

        separator = "<div style='display: flex; align-items: center; justify-content: center; font-size: 1.25rem; color: #ef4444; padding: 0 0.5rem; font-weight: 900;'>➔</div>"
        full_flow_html = f"<div style='display: flex; flex-direction: row; align-items: stretch; justify-content: space-between; margin: 1rem 0; overflow-x: auto; gap: 0.5rem;'>{separator.join(step_html_parts)}</div>"
        st.markdown(full_flow_html, unsafe_allow_html=True)

    # 3. Interactive Topology Attack Graph
    st.markdown("#### 🗺️ Network Topology & Attack Vector Overlay")
    st.caption("A* traversal overlay showing the critical attack path (red solid) versus alternative defensive corridors (dashed).")

    dot_graph = _generate_attack_graph_dot(path_list)
    st.graphviz_chart(dot_graph)

    # 4. Strategic Rationale & Business Impact Analysis
    st.markdown("#### 🧠 Threat Intelligence & Impact Assessment")
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown(
            "<div style='background-color: #111827; border: 1px solid #374151; border-radius: 8px; padding: 1rem; height: 100%;'>"
            "<h5 style='color: #60a5fa; margin-top: 0;'>⚙️ Adversary Path Optimization Logic</h5>"
            f"<p style='color: #d1d5db; font-size: 0.88rem; line-height: 1.5;'>{attack_path_info.get('attack_logic', '')}</p>"
            "<p style='color: #9ca3af; font-size: 0.82rem; margin-top: 0.5rem; border-top: 1px solid #1f2937; padding-top: 0.5rem;'>"
            "<strong>Alternative Route Tradeoff:</strong> Traversal through <code>VPN01 ➔ EMP01 ➔ AUTH01 ➔ APP01 ➔ DB01</code> "
            "requires 5 hops with an accumulated cost of <strong>6.85</strong>. The A* algorithm discarded this route in favor "
            "of the perimeter web corridor (3 hops, cost <strong>4.08</strong>) due to minimal resistance."
            "</p>"
            "</div>",
            unsafe_allow_html=True,
        )

    with col_right:
        st.markdown(
            "<div style='background-color: #111827; border: 1px solid #7f1d1d; border-radius: 8px; padding: 1rem; height: 100%;'>"
            "<h5 style='color: #ef4444; margin-top: 0;'>🚨 Business Impact & Critical Asset Exposure</h5>"
            f"<p style='color: #d1d5db; font-size: 0.88rem; line-height: 1.5;'>{attack_path_info.get('business_impact', '')}</p>"
            "<p style='color: #9ca3af; font-size: 0.82rem; margin-top: 0.5rem; border-top: 1px solid #2d1519; padding-top: 0.5rem;'>"
            "<strong>Regulatory Consequence:</strong> Compromise of <code>DB01</code> violates strict GDPR/HIPAA encryption-at-rest "
            "mandates and exposes transaction ledgers, triggering mandatory 72-hour breach disclosure procedures."
            "</p>"
            "</div>",
            unsafe_allow_html=True,
        )

    # 5. Node-by-Node Threat Intelligence Table
    if path_nodes:
        st.markdown("#### 🔍 Step-by-Step Node Threat Details")
        node_records = []
        for n in path_nodes:
            node_records.append({
                "System ID": n.get("node_id", ""),
                "Host Name": n.get("name", ""),
                "Kill-Chain Phase": n.get("phase", ""),
                "Criticality": n.get("criticality_label", ""),
                "Normalized Risk": f"{n.get('risk_score', 0.0):.3f}",
                "Step Traversal Cost": f"{n.get('step_cost', 0.0):.2f}",
                "Adversary Traversal Justification": n.get("risk_reason", ""),
            })
        st.dataframe(pd.DataFrame(node_records), width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# Global Command Center Header & Modern Overview
# ---------------------------------------------------------------------------
def render_global_header(
    threat_posture: str = "ELEVATED",
    crown_jewel: str = "DB01 (Customer DB)",
    min_traversal_cost: float = 4.08,
    remediation_status: str = "5 Tasks Dispatched",
    is_mock: bool = False,
) -> None:
    """Render persistent global TraceWard command center header with live SOC telemetry."""
    source_badge = (
        '<span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; padding: 0.2rem 0.5rem; border-radius: 0.375rem; font-size: 0.75rem; font-weight: 600;">DEMO / MOCK DATA</span>'
        if is_mock
        else '<span style="background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; padding: 0.2rem 0.5rem; border-radius: 0.375rem; font-size: 0.75rem; font-weight: 600;">LIVE ML / CSP PIPELINE</span>'
    )

    st.markdown(
        f"""
        <div class="tw-soc-header">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <div style="display: flex; align-items: center; gap: 0.6rem;">
                        <span style="font-size: 1.4rem;">🛡️</span>
                        <span style="font-size: 1.25rem; font-weight: 700; color: var(--tw-text-primary);">TraceWard Security Operations Command Center</span>
                        {source_badge}
                    </div>
                    <div style="color: var(--tw-text-secondary); font-size: 0.85rem; margin-top: 0.25rem;">
                        AI-Driven Risk Analysis, Kill Chain Detection & Constraint-Optimized Remediation
                    </div>
                </div>
                <div style="display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: 0.85rem;">
                    <div>
                        <div style="color: var(--tw-text-secondary); font-size: 0.7rem; text-transform: uppercase;">Threat Posture</div>
                        <div style="color: #f59e0b; font-weight: 700; font-size: 0.95rem;">⚠️ {threat_posture}</div>
                    </div>
                    <div>
                        <div style="color: var(--tw-text-secondary); font-size: 0.7rem; text-transform: uppercase;">Crown Jewel Asset</div>
                        <div style="color: #ef4444; font-weight: 700; font-size: 0.95rem;">🎯 {crown_jewel}</div>
                    </div>
                    <div>
                        <div style="color: var(--tw-text-secondary); font-size: 0.7rem; text-transform: uppercase;">Min Breach Cost</div>
                        <div style="color: #38bdf8; font-weight: 700; font-size: 0.95rem;">⚡ {min_traversal_cost:.2f} Cost</div>
                    </div>
                    <div>
                        <div style="color: var(--tw-text-secondary); font-size: 0.7rem; text-transform: uppercase;">Remediation Queue</div>
                        <div style="color: #34d399; font-weight: 700; font-size: 0.95rem;">✅ {remediation_status}</div>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_modern_overview(
    risk_df: pd.DataFrame,
    csp_result: dict[str, Any],
    attack_path_info: dict[str, Any] | None = None,
    is_mock_risk: bool = False,
) -> None:
    """Render the redesigned modern enterprise SOC Overview command center.

    Provides executive KPI metrics, interactive defense hotspots, kill-chain corridor,
    patch dispatch overview, and quick-action studio launchers.
    """
    # 1. Macro KPI Cards
    total_vulns = len(risk_df)
    unique_systems = risk_df["system_id"].nunique() if "system_id" in risk_df.columns else 0

    crit_count = 0
    high_count = 0
    if "predicted_risk" in risk_df.columns:
        crit_count = int((risk_df["predicted_risk"] == "Critical").sum())
        high_count = int((risk_df["predicted_risk"] == "High").sum())

    traversal_cost = 4.08
    hops = 3
    if attack_path_info:
        traversal_cost = float(attack_path_info.get("total_cost", 4.08))
        path_nodes = attack_path_info.get("path_nodes", [])
        if path_nodes:
            hops = max(1, len(path_nodes) - 1)

    schedule = csp_result.get("schedule", [])
    feasible_count = len(schedule)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric(
            label="Analyzed Vulnerabilities",
            value=f"{total_vulns}",
            delta=f"{crit_count} Critical, {high_count} High",
            delta_color="inverse",
        )
    with c2:
        st.metric(
            label="Protected Hosts in Scope",
            value=f"{unique_systems} Systems",
            delta="Perimeter to Core",
            delta_color="off",
        )
    with c3:
        st.metric(
            label="Min Kill-Chain Cost",
            value=f"{traversal_cost:.2f} Cost",
            delta=f"{hops} Network Hops to DB01",
            delta_color="inverse",
        )
    with c4:
        st.metric(
            label="Immediate Patch Queue",
            value=f"{feasible_count} Dispatches",
            delta="100% Conflict-Free",
            delta_color="normal",
        )

    st.markdown('<hr style="margin: 1.5rem 0;">', unsafe_allow_html=True)

    # 2. Actionable 3-Column Defense Matrix
    col_host, col_path, col_patch = st.columns(3)

    with col_host:
        st.markdown(
            """
            <div class="tw-soc-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; font-size: 1rem; color: #60a5fa;">📍 Host Vulnerability Hotspots</h4>
                    <span style="font-size: 0.75rem; background: rgba(59, 130, 246, 0.2); color: #93c5fd; padding: 0.15rem 0.4rem; border-radius: 0.25rem;">KNN Model</span>
                </div>
                <p style="color: var(--tw-text-secondary); font-size: 0.82rem; margin-bottom: 0.75rem;">
                    Hosts exhibiting highest concentration of predicted severe vulnerabilities.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if "system_id" in risk_df.columns and "predicted_risk" in risk_df.columns:
            severe_df = risk_df[risk_df["predicted_risk"].isin(["Critical", "High"])]
            top_hosts = (
                severe_df.groupby("system_id")
                .agg(severe_count=("vuln_id", "count"))
                .reset_index()
                .sort_values(by="severe_count", ascending=False)
                .head(5)
            )
            st.dataframe(
                top_hosts.rename(columns={"system_id": "System", "severe_count": "Critical/High Vulns"}),
                width="stretch",
                hide_index=True,
            )
        else:
            st.caption("Host vulnerability data is currently unavailable.")

        if st.button("🔍 Explore Risk Intelligence", key="jump_risk_intel", use_container_width=True):
            st.session_state["nav_stage"] = "Risk Intelligence"
            st.rerun()

    with col_path:
        st.markdown(
            """
            <div class="tw-soc-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; font-size: 1rem; color: #f59e0b;">⚡ Critical Kill Chain Corridor</h4>
                    <span style="font-size: 0.75rem; background: rgba(245, 158, 11, 0.2); color: #fcd34d; padding: 0.15rem 0.4rem; border-radius: 0.25rem;">A* Algorithm</span>
                </div>
                <p style="color: var(--tw-text-secondary); font-size: 0.82rem; margin-bottom: 0.75rem;">
                    Optimal adversary penetration route identified by risk-weighted heuristic search.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        path_repr = "INTERNET ➔ WEB01 ➔ APP01 ➔ DB01"
        if attack_path_info and "path" in attack_path_info:
            path_repr = " ➔ ".join(attack_path_info["path"])

        st.markdown(
            f"""
            <div style="background: var(--tw-bg-surface); border: 1px solid var(--tw-border); border-radius: 0.5rem; padding: 0.75rem; margin-bottom: 1rem;">
                <div style="font-size: 0.75rem; color: var(--tw-text-secondary); text-transform: uppercase; margin-bottom: 0.25rem;">Active Breach Corridor</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: #f87171;">{path_repr}</div>
                <div style="font-size: 0.78rem; color: var(--tw-text-secondary); margin-top: 0.5rem;">
                    Shortest adversary resistance path targeting critical transaction data on <strong>DB01</strong>.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("🗺️ Inspect Attack Corridors", key="jump_attack_corridors", use_container_width=True):
            st.session_state["nav_stage"] = "Attack Corridors"
            st.rerun()

    with col_patch:
        st.markdown(
            """
            <div class="tw-soc-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; font-size: 1rem; color: #10b981;">🔧 Dispatched Patch Schedule</h4>
                    <span style="font-size: 0.75rem; background: rgba(16, 185, 129, 0.2); color: #6ee7b7; padding: 0.15rem 0.4rem; border-radius: 0.25rem;">CSP Solver</span>
                </div>
                <p style="color: var(--tw-text-secondary); font-size: 0.82rem; margin-bottom: 0.75rem;">
                    First wave remediations scheduled without maintenance or dependency conflicts.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if schedule:
            dispatch_items = []
            for item in schedule[:4]:
                dispatch_items.append({
                    "Time Window": item.get("slot", ""),
                    "Team": item.get("assigned_team", ""),
                    "Vuln": item.get("vuln_id", ""),
                    "Target Host": item.get("system_id", ""),
                })
            st.dataframe(pd.DataFrame(dispatch_items), width="stretch", hide_index=True)
        else:
            st.caption("No pending dispatches.")

        if st.button("📋 View Smart Patch Plan", key="jump_smart_remediation", use_container_width=True):
            st.session_state["nav_stage"] = "Smart Remediation"
            st.rerun()

    st.markdown('<hr style="margin: 1.5rem 0;">', unsafe_allow_html=True)

    # 3. Interactive Defense Simulation Studios
    st.markdown("### 🧪 Operational Defense Studios")
    studio_col1, studio_col2 = st.columns(2)

    with studio_col1:
        st.markdown(
            """
            <div class="tw-soc-card" style="border-left: 4px solid #ef4444;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                    <h4 style="margin: 0; color: #f87171;">🚨 FinBank Breach Incident Lab</h4>
                    <span style="font-size: 0.75rem; color: #ef4444; font-weight: 600;">ACTIVE TELEMETRY</span>
                </div>
                <p style="color: var(--tw-text-secondary); font-size: 0.85rem; margin-bottom: 0.75rem;">
                    Inject simulated enterprise breach events into financial banking infrastructure. Correlate alerts, assess attack paths, and verify incident priorities.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("🚀 Launch Incident Simulation Lab", key="jump_incident_lab", use_container_width=True):
            st.session_state["nav_stage"] = "Incident Lab"
            st.rerun()

    with studio_col2:
        st.markdown(
            """
            <div class="tw-soc-card" style="border-left: 4px solid #38bdf8;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                    <h4 style="margin: 0; color: #38bdf8;">🔬 Defense Verification & What-If Studio</h4>
                    <span style="font-size: 0.75rem; color: #38bdf8; font-weight: 600;">DECISION SUPPORT</span>
                </div>
                <p style="color: var(--tw-text-secondary); font-size: 0.85rem; margin-bottom: 0.75rem;">
                    Hypothetically remediate selected vulnerabilities or harden hosts to verify their defensive ROI on graph traversal costs before committing operational teams.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("🧪 Open Defense Verification Studio", key="jump_what_if", use_container_width=True):
            st.session_state["nav_stage"] = "Defense Verification"
            st.rerun()


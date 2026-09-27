"""Reusable UI/design layer for the TraceWard Streamlit dashboard."""



from __future__ import annotations



import json

from pathlib import Path

from typing import Any



import pandas as pd

import streamlit as st

from dashboard.overview_components import (
    render_soc_header,
    render_kpi_cards,
    render_top_system_vulnerabilities,
    render_network_risk_overview,
    render_active_attack_path,
    render_smart_remediation_queue,
    render_detection_defense_status,
    render_operational_studios,
    render_campus_asset_explorer,
    render_faculty_demo_guide,
)
from dashboard.asset_metadata import (
    get_asset,
    get_asset_name,
    format_asset_label,
    get_system_business_impact,
)


# ---------------------------------------------------------------------------
# HTML Safe Renderer Helper (prevents Markdown code-block escaping)
# ---------------------------------------------------------------------------
def render_html(html_str: str) -> None:
    """Render HTML safely without triggering Markdown indented code block syntax."""
    clean = "".join(line.strip() for line in html_str.splitlines() if line.strip())
    st.markdown(clean, unsafe_allow_html=True)






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
    """Inject custom CSS for an enterprise SOC command center aesthetic in Dark or Light mode."""
    is_light = theme_mode.lower() == "light"
    if is_light:
        bg_base = "#f8fafc"
        bg_surface = "rgba(255, 255, 255, 0.92)"
        bg_elevated = "#f1f5f9"
        border = "#cbd5e1"
        text_primary = "#0f172a"
        text_secondary = "#475569"
        shadow = "rgba(0, 0, 0, 0.05)"
        header_bg = "linear-gradient(135deg, rgba(255, 255, 255, 0.95) 0%, rgba(241, 245, 249, 0.9) 100%)"
        card_bg = "rgba(255, 255, 255, 0.88)"
        card_border = "#e2e8f0"
        btn_bg = "#ffffff"
        btn_hover = "#f1f5f9"
        glow = "rgba(37, 99, 235, 0.15)"
        code_bg = "#f1f5f9"
    else:
        bg_base = "#050B18"
        bg_surface = "rgba(10, 20, 40, 0.75)"
        bg_elevated = "#0d1b33"
        border = "rgba(56, 189, 248, 0.15)"
        text_primary = "#f8fafc"
        text_secondary = "#94a3b8"
        shadow = "rgba(0, 0, 0, 0.55)"
        header_bg = "linear-gradient(135deg, rgba(10, 20, 40, 0.85) 0%, rgba(15, 30, 60, 0.7) 100%)"
        card_bg = "rgba(10, 20, 40, 0.7)"
        card_border = "rgba(56, 189, 248, 0.15)"
        btn_bg = "rgba(15, 25, 50, 0.8)"
        btn_hover = "rgba(30, 50, 90, 0.9)"
        glow = "rgba(59, 130, 246, 0.25)"
        code_bg = "#091224"

    css = f"""
    <style>
    :root {{
        --tw-bg-base: {bg_base};
        --tw-bg-surface: {bg_surface};
        --tw-bg-elevated: {bg_elevated};
        --tw-border: {border};
        --tw-text-primary: {text_primary};
        --tw-text-secondary: {text_secondary};
        --tw-accent-blue: #3b82f6;
        --tw-accent-teal: #10b981;
        --tw-accent-orange: #f59e0b;
        --tw-accent-red: #ef4444;
        --tw-accent-purple: #8b5cf6;
        --tw-risk-low: #10b981;
        --tw-risk-medium: #f59e0b;
        --tw-risk-high: #f97316;
        --tw-risk-critical: #ef4444;
    }}

    * {{
        box-sizing: border-box;
    }}

    /* Hide Streamlit default chrome & deploy button */
    header[data-testid="stHeader"] {{
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
    }}
    #MainMenu, footer {{
        visibility: hidden !important;
    }}

    body {{
        background-color: var(--tw-bg-base);
        color: var(--tw-text-primary);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    }}

    .stApp {{
        background-color: var(--tw-bg-base);
    }}

    .main .block-container {{
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        max-width: 1540px;
    }}

    [data-testid="stVerticalBlock"] {{
        gap: 0.45rem !important;
    }}

    h1, h2, h3, h4, h5, h6 {{
        color: var(--tw-text-primary) !important;
        font-weight: 600;
        letter-spacing: -0.02em;
    }}

    /* Sidebar Navigation Styling */
    [data-testid="stSidebar"] {{
        background-color: #070d1e !important;
        border-right: 1px solid rgba(56, 189, 248, 0.1) !important;
    }}

    [data-testid="stSidebar"] .block-container {{
        padding-top: 1.25rem !important;
        padding-left: 1.15rem !important;
        padding-right: 1.15rem !important;
    }}

    /* Hide native radio circles in sidebar */
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label > div:first-child,
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label svg,
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] input[type="radio"] {{
        display: none !important;
    }}

    /* Style sidebar radio labels as sleek interactive pills */
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label {{
        background: transparent !important;
        border-radius: 8px !important;
        padding: 0.48rem 0.85rem !important;
        margin-bottom: 0.25rem !important;
        cursor: pointer !important;
        transition: all 0.15s ease-in-out !important;
        border: 1px solid transparent !important;
        width: 100% !important;
    }}

    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label:hover {{
        background: rgba(30, 58, 110, 0.35) !important;
        border-color: rgba(56, 189, 248, 0.2) !important;
    }}

    /* Active selected stage pill */
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked) {{
        background: #1d4ed8 !important;
        border: 1px solid #3b82f6 !important;
        box-shadow: 0 4px 12px rgba(29, 78, 216, 0.35) !important;
    }}

    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked) p,
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked) span {{
        color: #ffffff !important;
        font-weight: 700 !important;
    }}

    /* Glass Cards */
    .tw-soc-card {{
        background: {card_bg};
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid {card_border};
        border-radius: 12px;
        box-shadow: 0 8px 32px 0 {shadow};
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }}

    .tw-soc-card:hover {{
        border-color: rgba(59, 130, 246, 0.4);
    }}

    /* Embedded action buttons inside cards */
    .tw-action-btn {{
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 0.45rem !important;
        background: rgba(14, 28, 56, 0.95) !important;
        border: 1px solid rgba(56, 189, 248, 0.25) !important;
        border-radius: 8px !important;
        color: #93c5fd !important;
        text-decoration: none !important;
        font-size: 0.78rem !important;
        font-weight: 600 !important;
        padding: 0.45rem 1rem !important;
        width: 100% !important;
        transition: all 0.2s ease !important;
    }}

    .tw-action-btn:hover {{
        background: rgba(29, 78, 216, 0.45) !important;
        border-color: #3b82f6 !important;
        color: #ffffff !important;
        box-shadow: 0 0 14px rgba(59, 130, 246, 0.35) !important;
    }}

    /* Studio 100% Clickable Cards */
    .tw-studio-card {{
        display: flex !important;
        align-items: center !important;
        gap: 0.85rem !important;
        background: rgba(10, 20, 40, 0.7) !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        border: 1px solid rgba(56, 189, 248, 0.18) !important;
        border-radius: 12px !important;
        padding: 0.85rem 1rem !important;
        text-decoration: none !important;
        min-height: 80px !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4) !important;
    }}

    .tw-studio-card:hover {{
        transform: translateY(-2px) !important;
        border-color: rgba(59, 130, 246, 0.5) !important;
        box-shadow: 0 6px 20px rgba(59, 130, 246, 0.25) !important;
    }}

    /* Top Header theme pill button */
    div[data-testid="column"]:has(button[key="soc_theme_toggle_btn"]) button,
    button[key="soc_theme_toggle_btn"],
    button[data-testid="baseButton-secondary"]:has(> div:has(> p:contains("Dark"))),
    button[data-testid="baseButton-secondary"]:has(> div:has(> p:contains("Light"))) {{
        border-radius: 9999px !important;
        padding: 0.35rem 0.65rem !important;
        font-size: 0.72rem !important;
        background: var(--tw-bg-surface) !important;
        border: 1px solid var(--tw-border) !important;
        color: var(--tw-text-primary) !important;
        box-shadow: none !important;
    }}

    /* Dataframe and Tables */
    .stDataFrame {{
        background: {card_bg};
        border: 1px solid {card_border};
        border-radius: 0.5rem;
    }}

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {{
        background: {card_bg};
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

    /* Default Buttons */
    .stButton>button {{
        background: {btn_bg};
        color: var(--tw-text-primary);
        border: 1px solid {card_border};
        border-radius: 0.5rem;
        font-weight: 500;
        transition: all 0.2s ease-in-out;
    }}

    .stButton>button:hover {{
        background: {btn_hover};
        border-color: var(--tw-accent-blue);
        box-shadow: 0 0 12px {glow};
    }}

    code {{
        background-color: {code_bg};
        padding: 0.2rem 0.4rem;
        border-radius: 0.25rem;
        font-size: 0.9em;
    }}
    </style>
    """
    render_html(css)

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
    "Threat Discovery": "🏠",
    "Risk Intelligence": "🧠",
    "Attack Corridors": "🔀",
    "Smart Remediation": "🔧",
    "Incident Lab": "🧪",
    "Defense Verification": "🛡️",
}



STAGE_DESCRIPTIONS = {

    "Threat Discovery": "Macro posture & executive command",

    "Risk Intelligence": "KNN risk inference & K-Means clustering",

    "Attack Corridors": "A* kill chain detection & graph traversal",

    "Smart Remediation": "CSP conflict-free team dispatch schedule",

    "Incident Lab": "FinBank breach injection & correlation",

    "Defense Verification": "What-If hypothesis & mitigation impact",

}





def render_sidebar_navigation() -> str:
    """Render modern SOC sidebar navigation matching the approved enterprise reference."""
    with st.sidebar:
        # TraceWard SOC logo area
        render_html(
            """
            <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.25rem 0 0.75rem 0;">
                <div style="width: 38px; height: 38px; border-radius: 8px; background: rgba(59, 130, 246, 0.2); border: 1px solid #3b82f6; display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                    🛡️
                </div>
                <div>
                    <div style="font-size: 1.15rem; font-weight: 700; color: var(--tw-text-primary); letter-spacing: -0.01em; line-height: 1.1;">TraceWard <span style="color: #38bdf8;">SOC</span></div>
                    <div style="font-size: 0.65rem; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; margin-top: 0.15rem;">Cyber Defense Center</div>
                </div>
            </div>
            """
        )

        render_html('<div style="height: 0.5rem;"></div>')

        if "nav_stage" not in st.session_state:
            st.session_state["nav_stage"] = "Threat Discovery"

        current_index = 0
        if st.session_state["nav_stage"] in NAV_STAGES:
            current_index = NAV_STAGES.index(st.session_state["nav_stage"])

        selected_stage = st.radio(
            "Security Operations Stage",
            NAV_STAGES,
            index=current_index,
            format_func=lambda s: f"{STAGE_ICONS.get(s, '')}  {s}",
            key="soc_stage_radio",
            label_visibility="collapsed",
        )
        st.session_state["nav_stage"] = selected_stage

        render_html('<hr style="margin: 1.25rem 0 0.85rem 0; border: none; border-top: 1px solid var(--tw-border);">')

        # SYSTEM STATUS telemetry card
        render_html(
            """
            <div style="padding: 0.75rem; border-radius: 0.5rem; background: var(--tw-bg-surface); border: 1px solid var(--tw-border);">
                <div style="font-size: 0.68rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 700; margin-bottom: 0.5rem; letter-spacing: 0.05em;">CAMPUS SOC STATUS</div>
                <div style="font-size: 0.78rem; display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                    <span style="color: var(--tw-text-secondary); display: flex; align-items: center; gap: 0.3rem;">🖥️ Monitored Hosts</span>
                    <strong style="color: var(--tw-text-primary);">8</strong>
                </div>
                <div style="font-size: 0.78rem; display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                    <span style="color: var(--tw-text-secondary); display: flex; align-items: center; gap: 0.3rem;">🎯 Crown Jewel</span>
                    <strong style="color: var(--tw-text-primary);" title="Student Academic Database">DB01 (Student DB)</strong>
                </div>
                <div style="font-size: 0.78rem; display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                    <span style="color: var(--tw-text-secondary); display: flex; align-items: center; gap: 0.3rem;">⚙️ Pipeline Status</span>
                    <strong style="color: #10b981;">Armed</strong>
                </div>
                <div style="font-size: 0.78rem; display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: var(--tw-text-secondary); display: flex; align-items: center; gap: 0.3rem;">🌐 Environment</span>
                    <strong style="color: #38bdf8;" title="United International University — Simulated Digital Campus">UIU Campus</strong>
                </div>
            </div>
            """
        )

        render_html('<div style="height: 0.75rem;"></div>')

        # Links
        render_html(
            """
            <div style="display: flex; flex-direction: column; gap: 0.4rem; font-size: 0.78rem; padding: 0 0.2rem;">
                <div style="display: flex; align-items: center; gap: 0.4rem; color: var(--tw-text-secondary);">
                    <span>ℹ️</span> <span>About TraceWard</span>
                </div>
                <div style="display: flex; align-items: center; gap: 0.4rem; color: var(--tw-text-secondary);">
                    <span>📄</span> <span>Documentation</span>
                </div>
            </div>
            """
        )

        render_html('<div style="height: 1.5rem;"></div>')

        # Footer
        render_html(
            """
            <div style="font-size: 0.7rem; color: var(--tw-text-secondary); padding: 0 0.2rem;">
                <div style="font-weight: 600; color: var(--tw-text-secondary);">TraceWard v0.2</div>
                <div style="color: var(--tw-text-secondary); opacity: 0.8; margin-top: 0.1rem;">Autonomous Cyber Risk Defense</div>
            </div>
            """
        )

    return selected_stage

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

            name = get_asset_name(node_id)

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
            nid = n.get("node_id", "")
            node_records.append({
                "System ID": nid,
                "Campus Asset Name": get_asset_name(nid),
                "Kill-Chain Phase": n.get("phase", ""),
                "Criticality": n.get("criticality_label", ""),
                "Normalized Risk": f"{n.get('risk_score', 0.0):.3f}",
                "Step Traversal Cost": f"{n.get('step_cost', 0.0):.2f}",
                "Adversary Traversal Justification": n.get("risk_reason", ""),
            })

        st.dataframe(pd.DataFrame(node_records), width="stretch", hide_index=True)





def render_global_header(
    threat_posture: str = "ELEVATED",
    crown_jewel: str = "DB01 (Customer DB)",
    min_traversal_cost: float = 4.08,
    remediation_status: str = "5 Tasks Dispatched",
    is_mock: bool = False,
) -> None:
    """Render persistent global TraceWard command center header matching approved reference."""
    render_soc_header(
        threat_posture=threat_posture,
        crown_jewel=crown_jewel,
        min_traversal_cost=min_traversal_cost,
        remediation_status=remediation_status,
        is_mock=is_mock,
    )


def render_modern_overview(
    risk_df: pd.DataFrame,
    csp_result: dict[str, Any],
    attack_path_info: dict[str, Any] | None = None,
    is_mock_risk: bool = False,
) -> None:
    """Render the executive TraceWard SOC Command Center matching the approved design reference."""
    total_vulns = len(risk_df)
    unique_systems = risk_df["system_id"].nunique() if "system_id" in risk_df.columns else 7
    crit_count = int((risk_df["predicted_risk"] == "Critical").sum()) if "predicted_risk" in risk_df.columns else 60
    high_count = int((risk_df["predicted_risk"] == "High").sum()) if "predicted_risk" in risk_df.columns else 60
    traversal_cost = float(attack_path_info.get("total_cost", 4.08)) if attack_path_info else 4.08
    dispatch_count = len(csp_result.get("schedule", [])) if csp_result else 5

    # 1. Top KPI Row (4 Glass Cards with Sparklines)
    render_kpi_cards(
        total_vulns=total_vulns,
        total_hosts=unique_systems,
        traversal_cost=traversal_cost,
        dispatch_count=dispatch_count,
        crit_count=crit_count,
        high_count=high_count,
    )

    # 2. Main Intelligence Area (3 Equal Columns: Top Vulnerabilities, Risk Overview, Active Attack Path)
    col1, col2, col3 = st.columns(3)
    with col1:
        render_top_system_vulnerabilities()
    with col2:
        render_network_risk_overview()
    with col3:
        render_active_attack_path(traversal_cost)

    render_html('<div style="height: 0.35rem;"></div>')

    # 3. Second Intelligence Row (2 Columns: Smart Remediation Queue & Detection & Defense Status)
    col_left, col_right = st.columns([1.35, 1])
    with col_left:
        render_smart_remediation_queue()
    with col_right:
        render_detection_defense_status()

    render_html('<div style="height: 0.35rem;"></div>')

    # 4. Operational Studios (4 Columns, 100% Clickable Glass Cards)
    render_operational_studios()

    render_html('<div style="height: 0.5rem;"></div>')

    # 5. Campus Digital Asset Directory & Risk Profiler (Search, Filter & Profile Inspector)
    render_campus_asset_explorer(risk_df)

    render_html('<div style="height: 0.5rem;"></div>')

    # 6. Faculty Demonstration Scenario Walkthrough Guide
    render_faculty_demo_guide()

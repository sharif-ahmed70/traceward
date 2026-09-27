"""
TraceWard Enterprise SOC UI Theme
Presentation-only layer. No backend dependency.
"""

import streamlit as st


DARK = {
    "bg": "#07111F",
    "panel": "rgba(15, 27, 45, 0.82)",
    "border": "rgba(255,255,255,0.08)",
    "text": "#F8FAFC",
    "muted": "#94A3B8",
    "accent": "#38BDF8",
    "danger": "#FB7185",
    "success": "#34D399",
}

LIGHT = {
    "bg": "#F8FAFC",
    "panel": "rgba(255,255,255,0.9)",
    "border": "rgba(15,23,42,0.08)",
    "text": "#0F172A",
    "muted": "#475569",
    "accent": "#0284C7",
    "danger": "#E11D48",
    "success": "#059669",
}


def inject_soc_theme(mode="dark"):
    theme = DARK if mode == "dark" else LIGHT
    st.markdown(f"""
    <style>
    .stApp {{
        background: {theme['bg']};
        color: {theme['text']};
    }}
    .tw-card {{
        background: {theme['panel']};
        border: 1px solid {theme['border']};
        border-radius: 18px;
        padding: 18px;
        backdrop-filter: blur(14px);
        margin-bottom: 14px;
    }}
    .tw-title {{font-size:28px;font-weight:700;}}
    .tw-muted {{color:{theme['muted']};}}
    .tw-badge {{
        display:inline-block;
        padding:6px 12px;
        border-radius:999px;
        font-size:13px;
        margin-right:8px;
    }}
    .tw-blue {{background:rgba(56,189,248,.15);color:{theme['accent']};}}
    .tw-green {{background:rgba(52,211,153,.15);color:{theme['success']};}}
    .tw-red {{background:rgba(251,113,133,.15);color:{theme['danger']};}}
    </style>
    """, unsafe_allow_html=True)


def soc_card(title, body):
    st.markdown(f"""
    <div class="tw-card">
        <div class="tw-title">{title}</div>
        <div class="tw-muted">{body}</div>
    </div>
    """, unsafe_allow_html=True)

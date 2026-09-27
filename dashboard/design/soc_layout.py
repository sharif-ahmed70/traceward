"""TraceWard SOC presentation components."""

import streamlit as st


def render_global_header():
    st.markdown("""
    <div class="tw-card">
        <div class="tw-title">🛡️ TRACEWARD // ENTERPRISE SOC</div>
        <span class="tw-badge tw-blue">Live Threat Monitoring</span>
        <span class="tw-badge tw-green">Pipeline Healthy</span>
        <span class="tw-badge tw-red">Critical Assets Protected</span>
    </div>
    """, unsafe_allow_html=True)


def render_stage_navigation():
    stages = [
        "📊 Threat Discovery",
        "🎯 Risk Intelligence",
        "🕸️ Attack Corridors",
        "⏱️ Smart Remediation",
        "🚨 Incident Lab",
        "🧪 Defense Verification",
    ]
    return st.sidebar.radio("SOC Command Center", stages)


def render_overview_shell():
    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown('<div class="tw-card"><h3>Host Risk Ranking</h3><p>Critical assets and severity overview.</p></div>', unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="tw-card"><h3>Attack Path Intelligence</h3><p>Critical corridor visualization.</p></div>', unsafe_allow_html=True)

    with c3:
        st.markdown('<div class="tw-card"><h3>Remediation Dispatch</h3><p>CSP scheduling and response status.</p></div>', unsafe_allow_html=True)

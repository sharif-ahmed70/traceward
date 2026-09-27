"""Modular reusable UI components for TraceWard SOC Command Center Overview.

Matches the exact approved enterprise cybersecurity design reference.
"""

from __future__ import annotations

import datetime
from typing import Any
import pandas as pd
import streamlit as st


def render_html(html_str: str) -> None:
    """Render HTML safely without triggering Markdown indented code block syntax."""
    clean = "".join(line.strip() for line in html_str.splitlines() if line.strip())
    st.markdown(clean, unsafe_allow_html=True)


def render_soc_header(
    threat_posture: str = "ELEVATED",
    crown_jewel: str = "DB01",
    min_traversal_cost: float = 4.08,
    remediation_status: str = "5 Tasks Dispatched",
    is_mock: bool = False,
) -> None:
    """Render top enterprise SOC header with live status, clock, and the sole theme switcher."""
    now = datetime.datetime.now()
    clock_str = now.strftime("%b %d, %Y %H:%M:%S")

    col_title, col_telemetry = st.columns([1.6, 1.4])

    with col_title:
        title_html = """
        <div style="display: flex; flex-direction: column; justify-content: center; height: 100%;">
            <div style="font-size: 1.25rem; font-weight: 700; color: var(--tw-text-primary); letter-spacing: -0.01em; line-height: 1.2;">
                TraceWard Security Operations Command Center
            </div>
            <div style="font-size: 0.78rem; color: var(--tw-text-secondary); margin-top: 0.2rem;">
                AI-Driven Risk Analysis, Kill Chain Detection &amp; Constraint-Optimized Remediation
            </div>
        </div>
        """
        render_html(title_html)

    with col_telemetry:
        c_status, c_env, c_clock, c_theme = st.columns([1.1, 1.0, 1.3, 0.9])

        with c_status:
            render_html(
                """
                <div style="background: var(--tw-bg-surface); border: 1px solid var(--tw-border); border-radius: 9999px; padding: 0.35rem 0.65rem; display: flex; align-items: center; gap: 0.4rem; justify-content: center;">
                    <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10b981; box-shadow: 0 0 6px #10b981;"></span>
                    <span style="font-size: 0.72rem; color: var(--tw-text-secondary); font-weight: 500;">System Status</span>
                    <strong style="font-size: 0.72rem; color: #10b981;">Online</strong>
                </div>
                """
            )

        with c_env:
            render_html(
                """
                <div style="background: var(--tw-bg-surface); border: 1px solid var(--tw-border); border-radius: 9999px; padding: 0.35rem 0.65rem; display: flex; align-items: center; gap: 0.4rem; justify-content: center;">
                    <span style="font-size: 0.8rem;">🏛️</span>
                    <span style="font-size: 0.72rem; color: var(--tw-text-secondary); font-weight: 500;">Environment</span>
                    <strong style="font-size: 0.72rem; color: #38bdf8;">FinBank</strong>
                </div>
                """
            )

        with c_clock:
            render_html(
                f"""
                <div style="background: var(--tw-bg-surface); border: 1px solid var(--tw-border); border-radius: 9999px; padding: 0.35rem 0.65rem; display: flex; align-items: center; gap: 0.4rem; justify-content: center;">
                    <span style="font-size: 0.8rem;">📅</span>
                    <strong style="font-size: 0.72rem; color: var(--tw-text-primary); white-space: nowrap;">{clock_str}</strong>
                </div>
                """
            )

        with c_theme:
            current_theme = st.session_state.get("ui_theme_mode", "Dark")
            theme_choice = st.radio(
                "Theme",
                ["Dark", "Light"],
                index=0 if current_theme == "Dark" else 1,
                horizontal=True,
                key="soc_global_theme_switcher",
                label_visibility="collapsed",
            )
            if theme_choice != current_theme:
                st.session_state["ui_theme_mode"] = theme_choice
                st.rerun()

    render_html('<div style="height: 0.75rem;"></div>')


def render_kpi_cards(
    total_vulns: int,
    total_hosts: int,
    traversal_cost: float,
    dispatch_count: int,
    crit_count: int = 60,
    high_count: int = 60,
) -> None:
    """Render row of 4 top KPI cards with sparkline bar charts matching the approved reference."""
    k1, k2, k3, k4 = st.columns(4)

    # Card 1: Analyzed Vulnerabilities
    with k1:
        render_html(
            f"""
            <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 120px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(139, 92, 246, 0.2); border: 1px solid rgba(139, 92, 246, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.1rem;">
                                🛡️
                            </div>
                            <span style="font-size: 0.75rem; color: var(--tw-text-secondary); font-weight: 600;">Analyzed Vulnerabilities</span>
                        </div>
                        <div style="font-size: 1.75rem; font-weight: 700; color: var(--tw-text-primary); line-height: 1.1;">{total_vulns}</div>
                        <div style="display: flex; align-items: center; gap: 0.4rem; margin-top: 0.4rem;">
                            <span style="background: rgba(239, 68, 68, 0.18); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); padding: 0.15rem 0.45rem; border-radius: 9999px; font-size: 0.68rem; font-weight: 700;">↑ 12% vs. last scan</span>
                        </div>
                    </div>
                    <!-- Sparkline Bars (Red) -->
                    <div style="display: flex; align-items: flex-end; gap: 3px; height: 36px; padding-top: 0.5rem;">
                        <div style="width: 4px; height: 30%; background: #ef4444; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 45%; background: #ef4444; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 35%; background: #ef4444; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 70%; background: #ef4444; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 95%; background: #ef4444; border-radius: 2px;"></div>
                    </div>
                </div>
            </div>
            """
        )

    # Card 2: Protected Hosts
    with k2:
        render_html(
            f"""
            <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 120px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.1rem;">
                                🖥️
                            </div>
                            <span style="font-size: 0.75rem; color: var(--tw-text-secondary); font-weight: 600;">Protected Hosts</span>
                        </div>
                        <div style="font-size: 1.75rem; font-weight: 700; color: var(--tw-text-primary); line-height: 1.1;">{total_hosts}</div>
                        <div style="display: flex; align-items: center; gap: 0.4rem; margin-top: 0.4rem;">
                            <span style="background: rgba(16, 185, 129, 0.18); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.15rem 0.45rem; border-radius: 9999px; font-size: 0.68rem; font-weight: 700;">All Systems Online</span>
                        </div>
                    </div>
                    <!-- Sparkline Bars (Teal) -->
                    <div style="display: flex; align-items: flex-end; gap: 3px; height: 36px; padding-top: 0.5rem;">
                        <div style="width: 4px; height: 40%; background: #10b981; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 60%; background: #10b981; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 75%; background: #10b981; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 90%; background: #10b981; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 100%; background: #10b981; border-radius: 2px;"></div>
                    </div>
                </div>
            </div>
            """
        )

    # Card 3: Min Kill-Chain Cost
    with k3:
        render_html(
            f"""
            <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 120px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(56, 189, 248, 0.2); border: 1px solid rgba(56, 189, 248, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.1rem;">
                                🔀
                            </div>
                            <span style="font-size: 0.75rem; color: var(--tw-text-secondary); font-weight: 600;">Min Kill-Chain Cost</span>
                        </div>
                        <div style="font-size: 1.75rem; font-weight: 700; color: var(--tw-text-primary); line-height: 1.1;">{traversal_cost:.2f}</div>
                        <div style="display: flex; align-items: center; gap: 0.4rem; margin-top: 0.4rem;">
                            <span style="background: rgba(16, 185, 129, 0.18); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.15rem 0.45rem; border-radius: 9999px; font-size: 0.68rem; font-weight: 700;">↓ 27% vs. baseline</span>
                        </div>
                    </div>
                    <!-- Sparkline Bars (Cyan) -->
                    <div style="display: flex; align-items: flex-end; gap: 3px; height: 36px; padding-top: 0.5rem;">
                        <div style="width: 4px; height: 30%; background: #38bdf8; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 50%; background: #38bdf8; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 65%; background: #38bdf8; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 80%; background: #38bdf8; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 100%; background: #38bdf8; border-radius: 2px;"></div>
                    </div>
                </div>
            </div>
            """
        )

    # Card 4: Patch Dispatches
    with k4:
        render_html(
            f"""
            <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 120px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                            <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(168, 85, 247, 0.2); border: 1px solid rgba(168, 85, 247, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.1rem;">
                                ⏱️
                            </div>
                            <span style="font-size: 0.75rem; color: var(--tw-text-secondary); font-weight: 600;">Patch Dispatches</span>
                        </div>
                        <div style="font-size: 1.75rem; font-weight: 700; color: var(--tw-text-primary); line-height: 1.1;">{dispatch_count}</div>
                        <div style="display: flex; align-items: center; gap: 0.4rem; margin-top: 0.4rem;">
                            <span style="background: rgba(16, 185, 129, 0.18); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.15rem 0.45rem; border-radius: 9999px; font-size: 0.68rem; font-weight: 700;">+ 30% Confidence</span>
                        </div>
                    </div>
                    <!-- Sparkline Bars (Purple) -->
                    <div style="display: flex; align-items: flex-end; gap: 3px; height: 36px; padding-top: 0.5rem;">
                        <div style="width: 4px; height: 35%; background: #a855f7; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 50%; background: #a855f7; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 60%; background: #a855f7; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 85%; background: #a855f7; border-radius: 2px;"></div>
                        <div style="width: 4px; height: 95%; background: #a855f7; border-radius: 2px;"></div>
                    </div>
                </div>
            </div>
            """
        )

    render_html('<div style="height: 0.5rem;"></div>')


def render_top_system_vulnerabilities() -> None:
    """Render Column 1: Top System Vulnerabilities matching the approved reference."""
    card_header = """
    <div style="display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.2rem;">
        <span style="color: #ef4444; font-size: 1rem;">⚠️</span>
        <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Top System Vulnerabilities</strong>
    </div>
    <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-bottom: 0.75rem;">
        Key assets ranked by predicted risk (higher = more critical).
    </div>
    <div style="display: grid; grid-template-columns: 24px 75px 65px 1fr; font-size: 0.68rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 600; padding: 0.2rem 0; border-bottom: 1px solid var(--tw-border);">
        <span>#</span>
        <span>System</span>
        <span>Criticality</span>
        <span>Risk Score</span>
    </div>
    """

    systems = [
        (1, "DB01", 93, "linear-gradient(90deg, #991b1b, #ef4444)"),
        (2, "APP01", 78, "linear-gradient(90deg, #9a3412, #ea580c)"),
        (3, "WEB01", 65, "linear-gradient(90deg, #b45309, #d97706)"),
        (4, "AUTH01", 38, "linear-gradient(90deg, #ca8a04, #eab308)"),
        (5, "VPN01", 21, "linear-gradient(90deg, #1d4ed8, #3b82f6)"),
    ]

    rows_html = []
    for rank, sys_id, score, gradient in systems:
        row = f"""
        <div style="display: grid; grid-template-columns: 24px 75px 65px 1fr; align-items: center; font-size: 0.8rem; padding: 0.45rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
            <span style="color: var(--tw-text-secondary);">{rank}</span>
            <strong style="color: var(--tw-text-primary);">{sys_id}</strong>
            <span style="color: var(--tw-text-secondary);">{score}</span>
            <div style="background: rgba(255,255,255,0.06); border-radius: 9999px; height: 10px; width: 100%; overflow: hidden;">
                <div style="background: {gradient}; width: {score}%; height: 100%; border-radius: 9999px;"></div>
            </div>
        </div>
        """
        rows_html.append(row)

    container_html = f"""
    <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 330px; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            {card_header}
            {"".join(rows_html)}
        </div>
    </div>
    """
    render_html(container_html)

    if st.button("🔍 Explore Risk Intelligence ➔", key="btn_col1_risk_intel", use_container_width=True):
        st.session_state["nav_stage"] = "Risk Intelligence"
        st.rerun()


def render_network_risk_overview() -> None:
    """Render Column 2: Network Risk Overview distribution bar chart matching the approved reference."""
    chart_header = """
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.2rem;">
        <div>
            <div style="display: flex; align-items: center; gap: 0.45rem;">
                <span style="color: #38bdf8; font-size: 1rem;">📊</span>
                <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Network Risk Overview</strong>
            </div>
            <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">
                Host risk distribution across the infrastructure.
            </div>
        </div>
        <!-- Legend -->
        <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.65rem; color: var(--tw-text-secondary);">
            <span style="display: flex; align-items: center; gap: 0.2rem;"><span style="width: 7px; height: 7px; background: #ef4444; border-radius: 50%;"></span> Critical</span>
            <span style="display: flex; align-items: center; gap: 0.2rem;"><span style="width: 7px; height: 7px; background: #ea580c; border-radius: 50%;"></span> High</span>
            <span style="display: flex; align-items: center; gap: 0.2rem;"><span style="width: 7px; height: 7px; background: #eab308; border-radius: 50%;"></span> Medium</span>
            <span style="display: flex; align-items: center; gap: 0.2rem;"><span style="width: 7px; height: 7px; background: #3b82f6; border-radius: 50%;"></span> Low</span>
        </div>
    </div>
    """

    # SVG Bar Chart matching the exact visual proportions in reference image
    svg_chart = """
    <div style="margin-top: 1rem; position: relative; height: 215px; width: 100%;">
        <svg viewBox="0 0 340 180" style="width: 100%; height: 100%; overflow: visible;">
            <!-- Grid Lines -->
            <line x1="25" y1="15" x2="335" y2="15" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="18" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">8</text>

            <line x1="25" y1="48" x2="335" y2="48" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="51" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">6</text>

            <line x1="25" y1="81" x2="335" y2="81" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="84" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">4</text>

            <line x1="25" y1="114" x2="335" y2="114" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="117" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">2</text>

            <line x1="25" y1="147" x2="335" y2="147" stroke="rgba(255,255,255,0.15)" />
            <text x="18" y="150" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">0</text>

            <!-- Bars -->
            <!-- DB (Critical / Red) -->
            <rect x="42" y="32" width="26" height="115" rx="3" fill="#ef4444" />
            <text x="55" y="162" fill="var(--tw-text-secondary)" font-size="9" text-anchor="middle">DB</text>

            <!-- WEB (High / Orange) -->
            <rect x="86" y="65" width="26" height="82" rx="3" fill="#ea580c" />
            <text x="99" y="162" fill="var(--tw-text-secondary)" font-size="9" text-anchor="middle">WEB</text>

            <!-- APP (High / Orange) -->
            <rect x="130" y="80" width="26" height="67" rx="3" fill="#ea580c" />
            <text x="143" y="162" fill="var(--tw-text-secondary)" font-size="9" text-anchor="middle">APP</text>

            <!-- AUTH (Medium / Amber) -->
            <rect x="174" y="105" width="26" height="42" rx="3" fill="#eab308" />
            <text x="187" y="162" fill="var(--tw-text-secondary)" font-size="9" text-anchor="middle">AUTH</text>

            <!-- VPN (Low / Blue) -->
            <rect x="218" y="120" width="26" height="27" rx="3" fill="#3b82f6" />
            <text x="231" y="162" fill="var(--tw-text-secondary)" font-size="9" text-anchor="middle">VPN</text>

            <!-- SWITCH (Low / Cyan) -->
            <rect x="262" y="120" width="26" height="27" rx="3" fill="#38bdf8" />
            <text x="275" y="162" fill="var(--tw-text-secondary)" font-size="8" text-anchor="middle">SWITCH</text>

            <!-- OTHER (Low / Dark Blue) -->
            <rect x="306" y="132" width="24" height="15" rx="3" fill="#1d4ed8" />
            <text x="318" y="162" fill="var(--tw-text-secondary)" font-size="8" text-anchor="middle">OTHER</text>
        </svg>
    </div>
    """

    chart_html = f"""
    <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 330px; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            {chart_header}
            {svg_chart}
        </div>
    </div>
    """
    render_html(chart_html)


def render_active_attack_path(total_cost: float = 4.08) -> None:
    """Render Column 3: Active Attack Path with vertical node progression matching approved reference."""
    header_html = f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.2rem;">
        <div>
            <div style="display: flex; align-items: center; gap: 0.45rem;">
                <span style="color: #38bdf8; font-size: 1rem;">🔀</span>
                <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Active Attack Path</strong>
            </div>
            <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">
                Most likely path to crown jewel (lowest cost).
            </div>
        </div>
        <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 0.2rem 0.5rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700;">
            Cost: {total_cost:.2f}
        </span>
    </div>
    """

    nodes = [
        (1, "INTERNET", "Initial Access (Phishing)", "#3b82f6", "🌐"),
        (2, "WEB01", "Exploit Public-Facing Service", "#ea580c", "🖥️"),
        (3, "APP01", "Lateral Movement", "#8b5cf6", "⚙️"),
        (4, "DB01", "Reach Crown Jewel", "#ef4444", "🎯"),
    ]

    steps_html = []
    for idx, (num, name, action, color, icon) in enumerate(nodes):
        connector = (
            f"""
            <div style="margin-left: 11px; width: 2px; height: 16px; background: {color}; opacity: 0.5;"></div>
            """
            if idx < len(nodes) - 1
            else ""
        )

        step = f"""
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.2rem 0;">
            <div style="display: flex; align-items: center; gap: 0.65rem;">
                <div style="width: 24px; height: 24px; border-radius: 50%; background: {color}; color: #ffffff; display: flex; align-items: center; justify-content: center; font-size: 0.72rem; font-weight: 700;">
                    {num}
                </div>
                <div>
                    <div style="font-size: 0.82rem; font-weight: 700; color: var(--tw-text-primary);">{name}</div>
                    <div style="font-size: 0.7rem; color: var(--tw-text-secondary);">{action}</div>
                </div>
            </div>
            <div style="font-size: 1.1rem; opacity: 0.85;">{icon}</div>
        </div>
        {connector}
        """
        steps_html.append(step)

    card_html = f"""
    <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 330px; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            {header_html}
            <div style="margin-top: 0.85rem;">
                {"".join(steps_html)}
            </div>
        </div>
    </div>
    """
    render_html(card_html)

    if st.button("🧭 View Full Attack Corridor ➔", key="btn_col3_attack_path", use_container_width=True):
        st.session_state["nav_stage"] = "Attack Corridors"
        st.rerun()


def render_smart_remediation_queue() -> None:
    """Render Row 3 Left: Smart Remediation Queue table matching approved reference."""
    header_html = """
    <div style="display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.2rem;">
        <span style="color: #38bdf8; font-size: 1rem;">🔧</span>
        <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Smart Remediation Queue</strong>
    </div>
    <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-bottom: 0.75rem;">
        AI-optimized patch plan with business impact awareness.
    </div>
    <div style="display: grid; grid-template-columns: 80px 75px 120px 1fr 80px; font-size: 0.68rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 600; padding: 0.2rem 0; border-bottom: 1px solid var(--tw-border);">
        <span>Priority</span>
        <span>System</span>
        <span>Vulnerability</span>
        <span>Recommended Action</span>
        <span>Est. Impact</span>
    </div>
    """

    tasks = [
        ("Critical", "#ef4444", "rgba(239,68,68,0.2)", "DB01", "CVE-2024-3094", "Apply security patch", "Low", "var(--tw-text-secondary)"),
        ("High", "#ea580c", "rgba(234,88,12,0.2)", "APP01", "CVE-2024-2187", "Update framework", "Medium", "#eab308"),
        ("Medium", "#eab308", "rgba(234,179,8,0.2)", "WEB01", "CVE-2024-1756", "Apply configuration fix", "Low", "var(--tw-text-secondary)"),
        ("Low", "#3b82f6", "rgba(59,130,246,0.2)", "AUTH01", "CVE-2024-0921", "Update dependency", "Low", "var(--tw-text-secondary)"),
    ]

    rows_html = []
    for prio, color, bg, sys_id, cve, action, impact, impact_color in tasks:
        row = f"""
        <div style="display: grid; grid-template-columns: 80px 75px 120px 1fr 80px; align-items: center; font-size: 0.78rem; padding: 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
            <div>
                <span style="background: {bg}; color: {color}; border: 1px solid {color}44; padding: 0.15rem 0.45rem; border-radius: 9999px; font-size: 0.68rem; font-weight: 700;">
                    {prio}
                </span>
            </div>
            <strong style="color: var(--tw-text-primary);">{sys_id}</strong>
            <span style="color: var(--tw-text-secondary); font-family: monospace; font-size: 0.74rem;">{cve}</span>
            <span style="color: var(--tw-text-primary); font-size: 0.78rem;">{action}</span>
            <span style="color: {impact_color}; font-weight: 600; font-size: 0.78rem;">{impact}</span>
        </div>
        """
        rows_html.append(row)

    container_html = f"""
    <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 270px; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            {header_html}
            {"".join(rows_html)}
        </div>
    </div>
    """
    render_html(container_html)

    if st.button("🔧 View Smart Patch Plan ➔", key="btn_row3_patch_plan", use_container_width=True):
        st.session_state["nav_stage"] = "Smart Remediation"
        st.rerun()


def render_detection_defense_status() -> None:
    """Render Row 3 Right: Detection & Defense Status with 4 circular donut charts matching approved reference."""
    header_html = """
    <div style="display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.2rem;">
        <span style="color: #38bdf8; font-size: 1rem;">🛡️</span>
        <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Detection &amp; Defense Status</strong>
    </div>
    <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-bottom: 0.75rem;">
        Simulation-based verification of security controls.
    </div>
    """

    # 4 circular gauges with conic gradients
    gauges = [
        ("94%", 94, "#10b981", "Detection Rate", "↑ 12%", "#10b981"),
        ("87%", 87, "#38bdf8", "False Positive", "↓ 8%", "#10b981"),
        ("76%", 76, "#8b5cf6", "Attack Simulation", "↑ 18%", "#8b5cf6"),
        ("92%", 92, "#f97316", "Control Coverage", "↑ 15%", "#10b981"),
    ]

    gauges_html = []
    for pct_str, pct, color, title, delta, delta_color in gauges:
        g = f"""
        <div style="display: flex; flex-direction: column; align-items: center; text-align: center;">
            <div style="position: relative; width: 66px; height: 66px; border-radius: 50%; background: conic-gradient({color} 0% {pct}%, rgba(255,255,255,0.08) {pct}% 100%); display: flex; align-items: center; justify-content: center;">
                <div style="width: 52px; height: 52px; border-radius: 50%; background: var(--tw-bg-base); display: flex; align-items: center; justify-content: center; font-size: 0.88rem; font-weight: 700; color: var(--tw-text-primary);">
                    {pct_str}
                </div>
            </div>
            <div style="font-size: 0.75rem; font-weight: 600; color: var(--tw-text-primary); margin-top: 0.5rem;">{title}</div>
            <div style="font-size: 0.68rem; font-weight: 700; color: {delta_color}; margin-top: 0.15rem;">{delta}</div>
        </div>
        """
        gauges_html.append(g)

    card_html = f"""
    <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 270px; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            {header_html}
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; margin-top: 1rem; align-items: center;">
                {"".join(gauges_html)}
            </div>
        </div>
    </div>
    """
    render_html(card_html)

    if st.button("🛡️ Open Defense Verification Studio ➔", key="btn_row3_defense_studio", use_container_width=True):
        st.session_state["nav_stage"] = "Defense Verification"
        st.rerun()


def render_operational_studios() -> None:
    """Render Row 4: Operational Studios matching approved reference."""
    section_title = """
    <div style="margin-top: 0.5rem; margin-bottom: 0.6rem;">
        <div style="display: flex; align-items: center; gap: 0.45rem;">
            <span style="color: #38bdf8; font-size: 1rem;">⚡</span>
            <strong style="color: var(--tw-text-primary); font-size: 0.98rem;">Operational Studios</strong>
        </div>
        <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-top: 0.1rem;">
            Access specialized modules for deeper analysis and operations.
        </div>
    </div>
    """
    render_html(section_title)

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        render_html(
            """
            <div class="tw-soc-card" style="padding: 0.9rem; min-height: 105px; display: flex; align-items: center; gap: 0.85rem; border-color: rgba(59, 130, 246, 0.35);">
                <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                    🧠
                </div>
                <div style="flex: 1;">
                    <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Risk Intelligence</div>
                    <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">Deep dive into vulnerabilities and asset risk</div>
                </div>
                <div style="font-size: 1rem; color: #60a5fa;">➔</div>
            </div>
            """
        )
        if st.button("Launch Risk Intelligence", key="btn_studio_launch_risk", use_container_width=True):
            st.session_state["nav_stage"] = "Risk Intelligence"
            st.rerun()

    with c2:
        render_html(
            """
            <div class="tw-soc-card" style="padding: 0.9rem; min-height: 105px; display: flex; align-items: center; gap: 0.85rem; border-color: rgba(245, 158, 11, 0.35);">
                <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(245, 158, 11, 0.2); border: 1px solid rgba(245, 158, 11, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                    🔀
                </div>
                <div style="flex: 1;">
                    <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Attack Corridors</div>
                    <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">Visualize and analyze attack paths</div>
                </div>
                <div style="font-size: 1rem; color: #fbbf24;">➔</div>
            </div>
            """
        )
        if st.button("Launch Attack Corridors", key="btn_studio_launch_corridors", use_container_width=True):
            st.session_state["nav_stage"] = "Attack Corridors"
            st.rerun()

    with c3:
        render_html(
            """
            <div class="tw-soc-card" style="padding: 0.9rem; min-height: 105px; display: flex; align-items: center; gap: 0.85rem; border-color: rgba(16, 185, 129, 0.35);">
                <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                    🔧
                </div>
                <div style="flex: 1;">
                    <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Smart Remediation</div>
                    <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">AI-optimized patch scheduling</div>
                </div>
                <div style="font-size: 1rem; color: #34d399;">➔</div>
            </div>
            """
        )
        if st.button("Launch Smart Remediation", key="btn_studio_launch_remediation", use_container_width=True):
            st.session_state["nav_stage"] = "Smart Remediation"
            st.rerun()

    with c4:
        render_html(
            """
            <div class="tw-soc-card" style="padding: 0.9rem; min-height: 105px; display: flex; align-items: center; gap: 0.85rem; border-color: rgba(168, 85, 247, 0.35);">
                <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(168, 85, 247, 0.2); border: 1px solid rgba(168, 85, 247, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                    🧪
                </div>
                <div style="flex: 1;">
                    <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Incident Simulation</div>
                    <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">Simulate real-world breach scenarios</div>
                </div>
                <div style="font-size: 1rem; color: #c084fc;">➔</div>
            </div>
            """
        )
        if st.button("Launch Incident Simulation", key="btn_studio_launch_incident", use_container_width=True):
            st.session_state["nav_stage"] = "Incident Lab"
            st.rerun()

"""Modular reusable UI components for TraceWard SOC Command Center Overview.

Matches the approved enterprise cybersecurity design reference and integrates the
United International University (Simulated Campus Environment) asset metadata layer.

DISCLAIMER:
Simulated higher education cybersecurity environment for academic research and faculty demonstration.
Does not represent actual production UIU infrastructure.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional
import pandas as pd
import streamlit as st

from dashboard.asset_metadata import (
    CAMPUS_ASSETS,
    UNIVERSITY_INFO,
    filter_assets,
    format_asset_label,
    get_all_assets,
    get_asset,
    get_asset_name,
    get_system_business_impact,
    get_system_vulnerability_context,
)


def render_html(html_str: str) -> None:
    """Render HTML safely without triggering Markdown indented code block syntax."""
    clean = "".join(line.strip() for line in html_str.splitlines() if line.strip())
    st.markdown(clean, unsafe_allow_html=True)


def render_soc_header(
    threat_posture: str = "ELEVATED",
    crown_jewel: str = "DB01 — Student Academic Database",
    min_traversal_cost: float = 4.08,
    remediation_status: str = "5 Tasks Dispatched",
    is_mock: bool = False,
) -> None:
    """Render top enterprise SOC header with live status, clock, and unified theme toggle matching approved reference."""
    now = datetime.datetime.now()
    clock_str = now.strftime("%b %d, %Y %H:%M:%S")

    col_title, col_telemetry = st.columns([1.55, 1.45])

    with col_title:
        title_html = """
        <div style="display: flex; flex-direction: column; justify-content: center; height: 100%;">
            <div style="font-size: 1.25rem; font-weight: 700; color: var(--tw-text-primary); letter-spacing: -0.01em; line-height: 1.2;">
                TraceWard Security Operations Command Center
            </div>
            <div style="font-size: 0.78rem; color: var(--tw-text-secondary); margin-top: 0.2rem;">
                United International University (Simulated Campus) — AI-Driven Cyber Defense &amp; Smart Remediation
            </div>
        </div>
        """
        render_html(title_html)

    with col_telemetry:
        c_status, c_env, c_clock, c_theme = st.columns([1.0, 1.15, 1.25, 0.8])

        with c_status:
            render_html(
                """
                <div style="background: var(--tw-bg-surface); border: 1px solid var(--tw-border); border-radius: 9999px; padding: 0.35rem 0.65rem; display: flex; align-items: center; gap: 0.4rem; justify-content: center;">
                    <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10b981; box-shadow: 0 0 6px #10b981;"></span>
                    <span style="font-size: 0.72rem; color: var(--tw-text-secondary); font-weight: 500;">Status</span>
                    <strong style="font-size: 0.72rem; color: #10b981;">Online</strong>
                </div>
                """
            )

        with c_env:
            render_html(
                """
                <div style="background: var(--tw-bg-surface); border: 1px solid var(--tw-border); border-radius: 9999px; padding: 0.35rem 0.65rem; display: flex; align-items: center; gap: 0.4rem; justify-content: center;" title="Simulated Higher Education Digital Ecosystem">
                    <span style="font-size: 0.8rem;">🏛️</span>
                    <span style="font-size: 0.72rem; color: var(--tw-text-secondary); font-weight: 500;">Env</span>
                    <strong style="font-size: 0.72rem; color: #38bdf8;">UIU Campus</strong>
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
            next_theme = "Light" if current_theme == "Dark" else "Dark"
            btn_label = "🌙 Dark" if current_theme == "Dark" else "☀️ Light"
            if st.button(btn_label, key="soc_theme_toggle_btn", use_container_width=True):
                st.session_state["ui_theme_mode"] = next_theme
                st.rerun()

    # Academic Simulation Notice Banner
    render_html(
        """
        <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 0.4rem 0.85rem; margin: 0.4rem 0 0.8rem 0; display: flex; align-items: center; justify-content: space-between; font-size: 0.74rem;">
            <div style="display: flex; align-items: center; gap: 0.5rem; color: #94a3b8;">
                <span style="color: #38bdf8; font-weight: 700;">ℹ️ ACADEMIC SIMULATION:</span>
                <span>Demonstrating autonomous AI defense on a simulated university digital campus model. Non-production research environment.</span>
            </div>
            <span style="color: #34d399; font-weight: 600; font-size: 0.7rem; background: rgba(16, 185, 129, 0.15); padding: 0.1rem 0.4rem; border-radius: 4px;">Verified Clean</span>
        </div>
        """
    )


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
            <a href="?stage=Risk+Intelligence" target="_self" style="text-decoration: none; display: block;">
                <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 120px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem;">
                                <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.1rem;">
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
                            <div style="width: 4px; height: 40%; background: #ef4444; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 60%; background: #ef4444; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 35%; background: #ef4444; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 80%; background: #ef4444; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 100%; background: #ef4444; border-radius: 2px;"></div>
                        </div>
                    </div>
                </div>
            </a>
            """
        )

    # Card 2: Protected Campus Hosts
    with k2:
        render_html(
            f"""
            <a href="?stage=Threat+Discovery" target="_self" style="text-decoration: none; display: block;">
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
                        <!-- Sparkline Bars (Green) -->
                        <div style="display: flex; align-items: flex-end; gap: 3px; height: 36px; padding-top: 0.5rem;">
                            <div style="width: 4px; height: 50%; background: #10b981; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 75%; background: #10b981; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 60%; background: #10b981; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 90%; background: #10b981; border-radius: 2px;"></div>
                            <div style="width: 4px; height: 100%; background: #10b981; border-radius: 2px;"></div>
                        </div>
                    </div>
                </div>
            </a>
            """
        )

    # Card 3: Min Kill-Chain Cost
    with k3:
        render_html(
            f"""
            <a href="?stage=Attack+Corridors" target="_self" style="text-decoration: none; display: block;">
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
            </a>
            """
        )

    # Card 4: Patch Dispatches
    with k4:
        render_html(
            f"""
            <a href="?stage=Smart+Remediation" target="_self" style="text-decoration: none; display: block;">
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
            </a>
            """
        )

    render_html('<div style="height: 0.5rem;"></div>')


def render_top_system_vulnerabilities() -> None:
    """Render Column 1: Top System Vulnerabilities with human-readable campus asset context."""
    card_header = """
    <div style="display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.2rem;">
        <span style="color: #ef4444; font-size: 1rem;">⚠️</span>
        <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Top System Vulnerabilities</strong>
    </div>
    <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-bottom: 0.75rem;">
        Campus assets ranked by predicted risk (higher = more critical).
    </div>
    <div style="display: grid; grid-template-columns: 24px 130px 45px 1fr; font-size: 0.68rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 600; padding: 0.2rem 0; border-bottom: 1px solid var(--tw-border);">
        <span>#</span>
        <span>Campus Asset</span>
        <span>Score</span>
        <span>Risk Profile</span>
    </div>
    """

    systems = [
        (1, "DB01", "Student Academic DB", 93, "linear-gradient(90deg, #991b1b, #ef4444)"),
        (2, "APP01", "UCAM Academic Manager", 78, "linear-gradient(90deg, #9a3412, #ea580c)"),
        (3, "WEB01", "University Public Web", 65, "linear-gradient(90deg, #b45309, #d97706)"),
        (4, "AUTH01", "Identity & SSO Gateway", 38, "linear-gradient(90deg, #ca8a04, #eab308)"),
        (5, "VPN01", "Faculty VPN Gateway", 21, "linear-gradient(90deg, #1d4ed8, #3b82f6)"),
    ]

    rows_html = []
    for rank, sys_id, name, score, gradient in systems:
        row = f"""
        <div style="display: grid; grid-template-columns: 24px 130px 45px 1fr; align-items: center; font-size: 0.8rem; padding: 0.45rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
            <span style="color: var(--tw-text-secondary);">{rank}</span>
            <div>
                <strong style="color: var(--tw-text-primary); font-size: 0.82rem;">{sys_id}</strong>
                <div style="font-size: 0.68rem; color: var(--tw-text-secondary); line-height: 1.1;">{name}</div>
            </div>
            <span style="color: var(--tw-text-secondary); font-weight: 600;">{score}</span>
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
                Campus host vulnerability distribution by severity tier.
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

    svg_chart = """
    <div style="margin-top: 1rem; position: relative; height: 215px; width: 100%;">
        <svg viewBox="0 0 340 180" style="width: 100%; height: 100%; overflow: visible;">
            <!-- Grid Lines -->
            <line x1="25" y1="15" x2="335" y2="15" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="18" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">8</text>

            <line x1="25" y1="50" x2="335" y2="50" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="53" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">6</text>

            <line x1="25" y1="85" x2="335" y2="85" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="88" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">4</text>

            <line x1="25" y1="120" x2="335" y2="120" stroke="rgba(255,255,255,0.06)" stroke-dasharray="2 2" />
            <text x="18" y="123" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">2</text>

            <line x1="25" y1="155" x2="335" y2="155" stroke="rgba(255,255,255,0.15)" />
            <text x="18" y="158" fill="var(--tw-text-secondary)" font-size="9" text-anchor="end">0</text>

            <!-- Bars for Campus Systems -->
            <!-- DB01 (Critical - Red) -->
            <rect x="36" y="32" width="22" height="123" rx="3" fill="#ef4444" />
            <text x="47" y="170" fill="var(--tw-text-secondary)" font-size="8.5" text-anchor="middle">DB01</text>

            <!-- WEB01 (High - Orange) -->
            <rect x="80" y="67" width="22" height="88" rx="3" fill="#ea580c" />
            <text x="91" y="170" fill="var(--tw-text-secondary)" font-size="8.5" text-anchor="middle">WEB01</text>

            <!-- APP01 (High - Orange) -->
            <rect x="124" y="85" width="22" height="70" rx="3" fill="#ea580c" />
            <text x="135" y="170" fill="var(--tw-text-secondary)" font-size="8.5" text-anchor="middle">APP01</text>

            <!-- AUTH01 (Medium - Yellow) -->
            <rect x="168" y="120" width="22" height="35" rx="3" fill="#eab308" />
            <text x="179" y="170" fill="var(--tw-text-secondary)" font-size="8.5" text-anchor="middle">AUTH</text>

            <!-- VPN01 (Low - Blue) -->
            <rect x="212" y="132" width="22" height="23" rx="3" fill="#3b82f6" />
            <text x="223" y="170" fill="var(--tw-text-secondary)" font-size="8.5" text-anchor="middle">VPN01</text>

            <!-- BACKUP01 (Critical Enclave) -->
            <rect x="256" y="132" width="22" height="23" rx="3" fill="#38bdf8" />
            <text x="267" y="170" fill="var(--tw-text-secondary)" font-size="8.5" text-anchor="middle">BACKUP</text>

            <!-- EMP01 (Workstations) -->
            <rect x="300" y="142" width="22" height="13" rx="3" fill="#6366f1" />
            <text x="311" y="170" fill="var(--tw-text-secondary)" font-size="8.5" text-anchor="middle">EMP01</text>
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
    """Render Column 3: Active Attack Path showing realistic adversary breach corridor toward student database."""
    header_html = f"""
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.2rem;">
        <div>
            <div style="display: flex; align-items: center; gap: 0.45rem;">
                <span style="color: #38bdf8; font-size: 1rem;">🔀</span>
                <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Active Attack Path</strong>
            </div>
            <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">
                A* shortest kill-chain toward Student Academic Database.
            </div>
        </div>
        <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 0.2rem 0.5rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700;">
            Cost: {total_cost:.2f}
        </span>
    </div>
    """

    nodes = [
        (1, "INTERNET", "External Threat Vector", "Adversary Phishing / Public Probe", "#3b82f6", "🌐"),
        (2, "WEB01", "University Public Web", "Exploits Outdated Nginx Reverse Proxy", "#ea580c", "🖥️"),
        (3, "APP01", "UCAM Academic Manager", "Lateral Movement via Spring Framework Flaw", "#8b5cf6", "⚙️"),
        (4, "DB01", "Student Academic DB", "Full Compromise of Student Records & Grades", "#ef4444", "🎯"),
    ]

    steps_html = []
    for idx, (num, sys_id, name, action, color, icon) in enumerate(nodes):
        connector = (
            f"""
            <div style="margin-left: 11px; width: 2px; height: 14px; background: {color}; opacity: 0.45;"></div>
            """
            if idx < len(nodes) - 1
            else ""
        )

        step = f"""
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.15rem 0;">
            <div style="display: flex; align-items: center; gap: 0.65rem;">
                <div style="width: 24px; height: 24px; border-radius: 50%; background: {color}; color: #ffffff; display: flex; align-items: center; justify-content: center; font-size: 0.72rem; font-weight: 700;">
                    {num}
                </div>
                <div>
                    <div style="display: flex; align-items: baseline; gap: 0.35rem;">
                        <span style="font-size: 0.82rem; font-weight: 700; color: var(--tw-text-primary);">{sys_id}</span>
                        <span style="font-size: 0.72rem; color: #38bdf8; font-weight: 500;">— {name}</span>
                    </div>
                    <div style="font-size: 0.68rem; color: var(--tw-text-secondary); line-height: 1.1;">{action}</div>
                </div>
            </div>
            <div style="font-size: 1.05rem; opacity: 0.85;">{icon}</div>
        </div>
        {connector}
        """
        steps_html.append(step)

    card_html = f"""
    <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 330px; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            {header_html}
            <div style="margin-top: 0.75rem;">
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
    """Render Row 3 Left: Smart Remediation Queue table with campus department assignments."""
    header_html = """
    <div style="display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.2rem;">
        <span style="color: #38bdf8; font-size: 1rem;">🔧</span>
        <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Smart Remediation Queue</strong>
    </div>
    <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-bottom: 0.75rem;">
        Constraint-optimized patch plan prioritized by university business impact.
    </div>
    <div style="display: grid; grid-template-columns: 75px 125px 95px 1fr 75px; font-size: 0.68rem; color: var(--tw-text-secondary); text-transform: uppercase; font-weight: 600; padding: 0.2rem 0; border-bottom: 1px solid var(--tw-border);">
        <span>Priority</span>
        <span>Campus Asset</span>
        <span>Vulnerability</span>
        <span>Recommended Action</span>
        <span>Impact</span>
    </div>
    """

    tasks = [
        ("Critical", "#ef4444", "rgba(239,68,68,0.2)", "DB01", "Student Academic DB", "CVE-2024-3094", "Apply PostgreSQL access patch", "Low", "#34d399"),
        ("High", "#ea580c", "rgba(234,88,12,0.2)", "APP01", "UCAM Academic Mgr", "CVE-2024-2187", "Update Spring framework core", "Medium", "#fbbf24"),
        ("Medium", "#eab308", "rgba(234,179,8,0.2)", "WEB01", "Public Web Server", "CVE-2024-1756", "Apply Nginx reverse-proxy fix", "Low", "var(--tw-text-secondary)"),
        ("Low", "#3b82f6", "rgba(59,130,246,0.2)", "AUTH01", "Identity Gateway", "CVE-2024-0921", "Update Keycloak token validation", "Low", "var(--tw-text-secondary)"),
    ]

    rows_html = []
    for prio, color, bg, sys_id, sys_name, cve, action, impact, impact_color in tasks:
        row = f"""
        <div style="display: grid; grid-template-columns: 75px 125px 95px 1fr 75px; align-items: center; font-size: 0.78rem; padding: 0.45rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
            <div>
                <span style="background: {bg}; color: {color}; border: 1px solid {color}44; padding: 0.15rem 0.45rem; border-radius: 9999px; font-size: 0.68rem; font-weight: 700;">
                    {prio}
                </span>
            </div>
            <div>
                <strong style="color: var(--tw-text-primary); font-size: 0.8rem;">{sys_id}</strong>
                <div style="font-size: 0.68rem; color: var(--tw-text-secondary); line-height: 1.1;">{sys_name}</div>
            </div>
            <span style="color: var(--tw-text-secondary); font-family: monospace; font-size: 0.72rem;">{cve}</span>
            <span style="color: var(--tw-text-primary); font-size: 0.76rem;">{action}</span>
            <span style="color: {impact_color}; font-weight: 600; font-size: 0.76rem;">{impact}</span>
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
    """Render Row 3 Right: Detection & Defense Status matching approved reference."""
    header_html = """
    <div style="display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.2rem;">
        <span style="color: #38bdf8; font-size: 1rem;">🛡️</span>
        <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Detection &amp; Defense Status</strong>
    </div>
    <div style="font-size: 0.72rem; color: var(--tw-text-secondary); margin-bottom: 0.75rem;">
        Simulation-based verification of university defensive controls.
    </div>
    """

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
            <div style="font-size: 0.72rem; color: var(--tw-text-primary); font-weight: 600; margin-top: 0.45rem;">{title}</div>
            <div style="font-size: 0.65rem; color: {delta_color}; font-weight: 700; margin-top: 0.1rem;">{delta}</div>
        </div>
        """
        gauges_html.append(g)

    grid_html = f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-top: 0.5rem; padding: 0.5rem 0;">
        {"".join(gauges_html)}
    </div>
    """

    container_html = f"""
    <div class="tw-soc-card" style="padding: 1rem 1.15rem; min-height: 270px; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
            {header_html}
            {grid_html}
        </div>
    </div>
    """
    render_html(container_html)

    if st.button("🛡️ Open Defense Verification Studio ➔", key="btn_row3_defense_studio", use_container_width=True):
        st.session_state["nav_stage"] = "Defense Verification"
        st.rerun()


def render_operational_studios() -> None:
    """Render Row 4: Operational Studios as 4 sleek clickable cards matching approved reference."""
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.45rem; margin: 1.25rem 0 0.5rem 0;">
            <span style="color: #f59e0b; font-size: 1rem;">⚡</span>
            <strong style="color: var(--tw-text-primary); font-size: 0.95rem;">Operational Studios</strong>
        </div>
        <div style="font-size: 0.74rem; color: var(--tw-text-secondary); margin-bottom: 0.75rem;">
            Access specialized modules for deeper university threat analysis and defense orchestration.
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        render_html(
            """
            <a href="?stage=Risk+Intelligence" target="_self" style="text-decoration: none; display: block;">
                <div class="tw-studio-card" style="border-color: rgba(59, 130, 246, 0.35);">
                    <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                        🧠
                    </div>
                    <div style="flex: 1;">
                        <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Risk Intelligence</div>
                        <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">Deep dive into vulnerabilities and asset risk</div>
                    </div>
                    <div style="font-size: 1rem; color: #60a5fa;">➔</div>
                </div>
            </a>
            """
        )

    with c2:
        render_html(
            """
            <a href="?stage=Attack+Corridors" target="_self" style="text-decoration: none; display: block;">
                <div class="tw-studio-card" style="border-color: rgba(245, 158, 11, 0.35);">
                    <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(245, 158, 11, 0.2); border: 1px solid rgba(245, 158, 11, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                        🔀
                    </div>
                    <div style="flex: 1;">
                        <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Attack Corridors</div>
                        <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">Visualize and analyze attack paths</div>
                    </div>
                    <div style="font-size: 1rem; color: #fbbf24;">➔</div>
                </div>
            </a>
            """
        )

    with c3:
        render_html(
            """
            <a href="?stage=Smart+Remediation" target="_self" style="text-decoration: none; display: block;">
                <div class="tw-studio-card" style="border-color: rgba(16, 185, 129, 0.35);">
                    <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                        🔧
                    </div>
                    <div style="flex: 1;">
                        <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Smart Remediation</div>
                        <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">AI-optimized patch scheduling</div>
                    </div>
                    <div style="font-size: 1rem; color: #34d399;">➔</div>
                </div>
            </a>
            """
        )

    with c4:
        render_html(
            """
            <a href="?stage=Incident+Lab" target="_self" style="text-decoration: none; display: block;">
                <div class="tw-studio-card" style="border-color: rgba(168, 85, 247, 0.35);">
                    <div style="width: 40px; height: 40px; border-radius: 8px; background: rgba(168, 85, 247, 0.2); border: 1px solid rgba(168, 85, 247, 0.4); display: flex; align-items: center; justify-content: center; font-size: 1.3rem;">
                        🧪
                    </div>
                    <div style="flex: 1;">
                        <div style="font-size: 0.85rem; font-weight: 700; color: var(--tw-text-primary);">Incident Simulation</div>
                        <div style="font-size: 0.68rem; color: var(--tw-text-secondary); margin-top: 0.15rem;">Simulate real-world breach scenarios</div>
                    </div>
                    <div style="font-size: 1rem; color: #c084fc;">➔</div>
                </div>
            </a>
            """
        )


def render_campus_asset_explorer(risk_df: pd.DataFrame) -> None:
    """Render interactive Campus Digital Asset Directory, Search & Filter, and Detailed Asset Profile View."""
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 0.45rem; margin: 1.75rem 0 0.35rem 0;">
            <span style="color: #38bdf8; font-size: 1.15rem;">🏛️</span>
            <strong style="color: var(--tw-text-primary); font-size: 1.05rem;">Campus Digital Asset Directory &amp; Risk Profiler</strong>
        </div>
        <div style="font-size: 0.78rem; color: var(--tw-text-secondary); margin-bottom: 0.85rem;">
            Explore simulated university IT infrastructure with human-readable system mapping, business impact analysis, and active vulnerability metrics.
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("🔍 Search & Filter Campus Digital Assets", expanded=False):
        col_search, col_cat, col_crit, col_dept = st.columns([1.5, 1.0, 1.0, 1.2])

        with col_search:
            search_query = st.text_input(
                "Search Asset",
                placeholder="Asset ID, name, technology, impact...",
                key="asset_search_input",
            )

        with col_cat:
            cat_options = ["All", "Web Server", "Academic Application", "Database Server", "Security Infrastructure", "Storage & Disaster Recovery", "Perimeter Security Gateway", "Workstation Subnet"]
            cat_choice = st.selectbox("Category", cat_options, key="asset_cat_filter")

        with col_crit:
            crit_options = ["All", "Critical", "High", "Medium", "Low"]
            crit_choice = st.selectbox("Criticality", crit_options, key="asset_crit_filter")

        with col_dept:
            dept_options = ["All", "Center for IT Services", "Controller of Examinations", "Office of Admissions", "Central Library", "Academic Departments"]
            dept_choice = st.selectbox("Owner Department", dept_options, key="asset_dept_filter")

        matched_assets = filter_assets(
            search_query=search_query,
            category_filter=cat_choice,
            criticality_filter=crit_choice,
            owner_filter=dept_choice,
        )

        st.caption(f"Showing **{len(matched_assets)}** matching university systems.")

        if matched_assets:
            table_records = []
            for a in matched_assets:
                table_records.append({
                    "Asset ID": a["asset_id"],
                    "System Name": a["name"],
                    "Category": a["category"],
                    "Criticality": a["criticality"],
                    "Technology": a["technology"],
                    "Department": a["owner"],
                })
            st.dataframe(pd.DataFrame(table_records), width="stretch", hide_index=True)

    # Asset Profile Inspector
    st.markdown("##### 🔍 Campus Asset Profile Inspector")
    asset_keys = list(CAMPUS_ASSETS.keys())
    asset_keys = [k for k in asset_keys if k != "INTERNET"]

    col_select, col_quick_stats = st.columns([1.5, 2.5])
    with col_select:
        selected_asset_id = st.selectbox(
            "Select an Asset to Inspect",
            asset_keys,
            format_func=lambda sid: f"{sid} — {get_asset_name(sid, short=True)}",
            key="asset_inspector_select",
        )

    asset = get_asset(selected_asset_id)
    crit_badge_color = {
        "Critical": "#ef4444",
        "High": "#ea580c",
        "Medium": "#eab308",
        "Low": "#10b981",
    }.get(asset.get("criticality", "Medium"), "#3b82f6")

    # Calculate real-time vulnerability count for this system if risk_df exists
    sys_vulns = risk_df.loc[risk_df["system_id"] == selected_asset_id] if "system_id" in risk_df.columns else pd.DataFrame()
    vuln_count = len(sys_vulns)
    crit_vuln_count = int((sys_vulns["predicted_risk"] == "Critical").sum()) if "predicted_risk" in sys_vulns.columns else 0
    high_vuln_count = int((sys_vulns["predicted_risk"] == "High").sum()) if "predicted_risk" in sys_vulns.columns else 0

    profile_card_html = f"""
    <div class="tw-soc-card" style="padding: 1.25rem; border-color: {crit_badge_color}55; background: rgba(10, 20, 40, 0.85); margin-top: 0.5rem;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--tw-border); padding-bottom: 0.75rem;">
            <div>
                <div style="display: flex; align-items: center; gap: 0.6rem;">
                    <span style="font-size: 1.35rem; font-weight: 800; color: #38bdf8;">{asset['asset_id']}</span>
                    <span style="font-size: 1.15rem; font-weight: 700; color: var(--tw-text-primary);">— {asset['name']}</span>
                    <span style="background: {crit_badge_color}22; color: {crit_badge_color}; border: 1px solid {crit_badge_color}55; padding: 0.15rem 0.55rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase;">
                        {asset['criticality']} Criticality
                    </span>
                </div>
                <div style="font-size: 0.78rem; color: var(--tw-text-secondary); margin-top: 0.25rem;">
                    <strong>Department:</strong> {asset['owner']} &nbsp;|&nbsp; <strong>Category:</strong> {asset['category']} &nbsp;|&nbsp; <strong>Environment:</strong> {asset['environment']}
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.72rem; color: var(--tw-text-secondary);">Active Vulnerabilities</div>
                <div style="font-size: 1.35rem; font-weight: 800; color: {crit_badge_color};">{vuln_count} Detected</div>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-top: 1rem;">
            <div>
                <h6 style="color: #60a5fa; margin-bottom: 0.35rem; font-size: 0.85rem;">📋 Operational Purpose</h6>
                <p style="font-size: 0.82rem; color: var(--tw-text-primary); line-height: 1.45; margin-bottom: 0.85rem;">
                    {asset['purpose']}
                </p>

                <h6 style="color: #38bdf8; margin-bottom: 0.35rem; font-size: 0.85rem;">💻 Technology Stack &amp; Topology</h6>
                <div style="font-size: 0.8rem; color: var(--tw-text-secondary); margin-bottom: 0.85rem;">
                    <div><strong>Technology:</strong> {asset['technology']}</div>
                    <div style="margin-top: 0.25rem;"><strong>Connected Systems:</strong> {', '.join(asset.get('connected_systems', []))}</div>
                </div>

                <h6 style="color: #f59e0b; margin-bottom: 0.35rem; font-size: 0.85rem;">🔍 Vulnerability Simulation Context</h6>
                <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 6px; padding: 0.55rem 0.75rem; font-size: 0.78rem;">
                    <div><strong>Known Issue:</strong> {asset['vulnerability_context']['issue']}</div>
                    <div style="margin-top: 0.2rem;"><strong>Severity:</strong> <span style="color: #f59e0b; font-weight: 700;">{asset['vulnerability_context']['severity']}</span></div>
                    <div style="margin-top: 0.2rem;"><strong>Exploit Risk:</strong> {asset['vulnerability_context']['impact']}</div>
                </div>
            </div>

            <div>
                <h6 style="color: #ef4444; margin-bottom: 0.35rem; font-size: 0.85rem;">🚨 Campus Business Impact ("If Compromised")</h6>
                <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 6px; padding: 0.65rem 0.85rem; font-size: 0.82rem; color: #fca5a5; line-height: 1.45; margin-bottom: 0.85rem;">
                    {asset['business_impact']}
                </div>

                <h6 style="color: #34d399; margin-bottom: 0.35rem; font-size: 0.85rem;">🛡️ Recommended Defensive Actions</h6>
                <ul style="font-size: 0.8rem; color: var(--tw-text-secondary); margin-top: 0.25rem; padding-left: 1.15rem; line-height: 1.45;">
                    {''.join(f'<li style="margin-bottom: 0.25rem;">{action}</li>' for action in asset.get('recommended_actions', []))}
                </ul>
            </div>
        </div>
    </div>
    """
    render_html(profile_card_html)


def render_faculty_demo_guide() -> None:
    """Render 6-step faculty demonstration scenario guide."""
    with st.expander("🎓 Faculty Demonstration Walkthrough Guide (6-Step Academic Protocol)", expanded=False):
        st.markdown(
            """
            This protocol provides an evaluator walkthrough demonstrating how **TraceWard** protects a university digital ecosystem:

            1. **Step 1: Explore University Environment**  
               Review the **Overview Command Center**, telemetry indicators, and the **Campus Digital Asset Directory** above to understand the modeled higher education assets (`APP01 — UCAM`, `DB01 — Student Database`, `WEB01 — Public Portal`).
            2. **Step 2: Select & Profile a Vulnerable Asset**  
               Select `APP01` or `WEB01` in the **Asset Profile Inspector** to review operational dependencies, institutional ownership, and concrete business impacts if compromised.
            3. **Step 3: Analyze Risk Prediction with Explainability**  
               Navigate to **Risk Intelligence** (`🎯 Risk Level Prediction`). Review the KNN classifier predictions across the 7 CVSS dimensions, and select individual vulnerabilities to inspect factor-based explainability.
            4. **Step 4: Trace the Adversary Kill-Chain Corridor**  
               Navigate to **Attack Corridors** (`🔀 Attack Graph`). Observe the A* shortest-path heuristic finding the least-resistance corridor (`INTERNET ➔ WEB01 ➔ APP01 ➔ DB01`) threatening the crown jewel.
            5. **Step 5: Review Constraint-Optimized Remediation**  
               Navigate to **Smart Remediation** (`🔧 Patch Plan`). Observe how the backtracking CSP planner assigns patch tasks to operational teams under real-world maintenance window constraints.
            6. **Step 6: Verify Defense with What-If Simulation**  
               Navigate to **Defense Verification** (`🧪 What-If Analysis`). Simulate hardening `APP01` or `WEB01` by 50% and observe real-time traversal cost escalation, disrupting the adversary kill-chain.
            """
        )

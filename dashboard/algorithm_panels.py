"""Dashboard panels that expose the A* search and CSP solver internals for the demo/viva."""

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.csp_solver import compare_csp_strategies
from src.evaluation import csp_evaluation_cases

ATTACK_PATH_FILE = Path("artifacts/astar/attack_path.json")


def _load_attack_path_result():
    if not ATTACK_PATH_FILE.exists():
        return None
    with open(ATTACK_PATH_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def render_astar_analysis():
    """Edge costs, f/g/h trace and comparison with UCS/BFS."""
    result = _load_attack_path_result()
    if not result or "trace" not in result:
        st.info("Run `python main.py` to generate the A* search trace.")
        return

    st.subheader("A* Search Internals")
    st.markdown(
        "**Edge cost:** `c(u,v) = base_cost(u,v) x (1.5 - ease(v))`, where "
        "`ease(v) = 0.5 x KNN risk(v) + 0.5 x CVSS exploitability(v)`  \n"
        f"**Heuristic:** `{result['heuristic']}`: admissible and consistent, because every "
        "remaining hop costs at least the cheapest edge."
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("Path cost", result["total_cost"])
    c2.metric("Hops", len(result["path"]) - 1)
    c3.metric("Nodes expanded", result["nodes_expanded"])

    st.markdown("**Attack path hops (entry vulnerability = easiest flaw on the target host)**")
    st.dataframe(pd.DataFrame(result["hops"]), hide_index=True, width="stretch")

    st.markdown("**Expansion trace: f(n) = g(n) + h(n)**")
    st.dataframe(pd.DataFrame(result["trace"]), hide_index=True, width="stretch")

    st.markdown("**A* vs. uninformed search**")
    st.dataframe(pd.DataFrame(result["comparison"]), hide_index=True, width="stretch")

    st.markdown("**All attack paths to the target (exhaustive check)**")
    paths = pd.DataFrame(result["alternative_paths"])
    paths["path"] = paths["path"].map(" -> ".join)
    st.dataframe(paths, hide_index=True, width="stretch")


@st.cache_data
def _strategy_comparison():
    rows = []
    for case_name, case in csp_evaluation_cases().items():
        for row in compare_csp_strategies(case):
            rows.append({"case": case_name, "tasks": len(case.vulnerabilities), **row})
    return pd.DataFrame(rows)


def render_csp_analysis(csp_result):
    """Constraints, search statistics and strategy comparison."""
    st.subheader("CSP Solver Internals")
    st.markdown(f"**Search:** Backtracking + {', '.join(csp_result.get('heuristics', [])) or 'none'}")
    st.markdown("**Constraints enforced**")
    for line in csp_result.get("constraints", []):
        st.write(f"- {line}")

    stats = csp_result.get("stats", {})
    if stats:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Assignments", stats["assignments"])
        c2.metric("Backtracks", stats["backtracks"])
        c3.metric("Constraint checks", stats["constraint_checks"])
        c4.metric("Violations", len(csp_result.get("violations", [])))

    st.markdown(
        "**Strategy comparison:** *baseline* is the live plan. *stress* adds more tasks, "
        "and *overload* cannot fit the maintenance windows, so it is infeasible."
    )
    st.dataframe(_strategy_comparison(), hide_index=True, width="stretch")

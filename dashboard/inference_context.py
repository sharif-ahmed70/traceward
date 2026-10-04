"""Per-system context for the Interactive Model Inference panel.

The KNN class is the same on every host, so after each prediction this panel shows
what does change with the selected system (fix urgency) and keeps a short history,
making every click visibly produce a new result.
"""

import datetime

import pandas as pd
import streamlit as st

from dashboard.asset_metadata import get_asset_name

from src.astar_search import astar_search
from src.graph_builder import build_graph
from src.risk_engine import contextual_priority
from src.what_if_simulation import find_chokepoints

LEVEL_COLORS = {"Urgent": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#16a34a"}


@st.cache_data
def _network_context():
    graph = build_graph()
    path = astar_search(graph)["path"]
    chokepoints = find_chokepoints(graph)["hosts"]
    systems = {n["id"]: n for n in graph["nodes"]}
    return systems, path, chokepoints


def render_inference_context(system_id, predicted_risk, features):
    systems, path, chokepoints = _network_context()
    system = systems[system_id]
    name = get_asset_name(system_id, short=True)
    ctx = contextual_priority(predicted_risk, system, system_id in path, system_id in chokepoints)
    color = LEVEL_COLORS[ctx["level"]]

    st.markdown(f"#### What this means for the {name} ({system_id})")
    st.caption(
        "The risk class above comes only from the weakness's own characteristics, so it is the same "
        "on every server. How urgently it must be fixed depends on which server it is on:"
    )
    reasons = "".join(f"<li>{r}</li>" for r in ctx["reasons"])
    st.markdown(
        f"""<div style="border-left: 6px solid {color}; background: {color}14; padding: 0.8rem 1rem;
        border-radius: 8px; margin-bottom: 0.6rem;">
        <div style="font-size: 1.2rem; font-weight: 700; color: {color};">
        Fix priority on this server: {ctx['level']} (fix {ctx['fix_within']})</div>
        <div style="margin-top: 0.3rem;">Why:</div><ul style="margin: 0.2rem 0 0 1.1rem;">{reasons}</ul>
        <div style="font-size: 0.8rem; opacity: 0.75;">Priority score {ctx['score']}</div></div>""",
        unsafe_allow_html=True,
    )

    history = st.session_state.setdefault("inference_history", [])
    previous = history[0] if history else None
    history.insert(0, {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "server": f"{name} ({system_id})",
        "risk class": predicted_risk,
        "fix priority": ctx["level"],
        "fix within": ctx["fix_within"],
        "exploit probability": features["exploit_probability"],
    })
    del history[8:]

    if previous is not None:
        changes = []
        if previous["server"] != history[0]["server"]:
            changes.append(f"server {previous['server']} → {history[0]['server']}")
        if previous["risk class"] != predicted_risk:
            changes.append(f"risk class {previous['risk class']} → {predicted_risk}")
        if previous["fix priority"] != ctx["level"]:
            changes.append(f"fix priority {previous['fix priority']} → {ctx['level']}")
        if changes:
            st.info("**Compared with your last prediction:** " + "; ".join(changes) + ".")
        else:
            st.info("**Compared with your last prediction:** same inputs, same result.")

    st.markdown("**Your recent predictions** (newest first)")
    st.dataframe(pd.DataFrame(history), hide_index=True, width="stretch")

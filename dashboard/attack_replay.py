"""Step-by-step attack replay: shows how an attacker moves along an A* attack path.

Each step is narrated in plain language so non-technical viewers can follow it.
"""

import time
from pathlib import Path

import pandas as pd
import streamlit as st

from src.astar_search import edge_cost

RAW_VULNS = Path("data/raw/vulnerabilities.csv")


@st.cache_data
def _vuln_details():
    if not RAW_VULNS.exists():
        return {}
    return pd.read_csv(RAW_VULNS, keep_default_na=False).set_index("vuln_id").to_dict("index")


def _why_easy(vuln):
    """Plain-language reasons a vulnerability is attractive to an attacker."""
    reasons = []
    if vuln.get("privileges_required") == "None":
        reasons.append("no password is needed")
    if vuln.get("user_interaction") == "None":
        reasons.append("no employee has to click anything")
    if vuln.get("attack_complexity") == "Low":
        reasons.append("it is simple to pull off")
    prob = float(vuln.get("exploit_probability", 0) or 0)
    if prob >= 0.7:
        reasons.append(f"attackers use this kind of flaw often ({prob:.0%} likelihood)")
    return reasons


def _steps(graph, path):
    names = {n["id"]: n.get("name", n["id"]) for n in graph["nodes"]}
    details = _vuln_details()
    entry = graph.get("entry_vuln_map", {})
    steps = [{
        "title": f"The attacker starts on the {names[path[0]]}",
        "text": (f"Someone outside the organization wants to reach the {names[path[-1]]}. "
                 "They look for the easiest way in."),
        "effort": 0.0,
    }]
    effort = 0.0
    for i, (u, v) in enumerate(zip(path, path[1:]), start=1):
        effort += edge_cost(graph, u, v)
        vuln_id = entry.get(v, {}).get("vuln_id")
        vuln = details.get(vuln_id, {})
        reasons = _why_easy(vuln)
        how = f"using weakness **{vuln_id}**" if vuln_id else "using a known weakness"
        if reasons:
            how += ": " + ", ".join(reasons)
        is_goal = i == len(path) - 1
        steps.append({
            "title": (f"💥 Target reached: the {names[v]}" if is_goal
                      else f"Step {i}: breaks into the {names[v]}"),
            "text": f"From the {names[u]}, the attacker gets into the {names[v]} {how}.",
            "effort": round(effort, 2),
        })
    return steps


def _dot(graph, path, step):
    names = {n["id"]: n.get("name", n["id"]) for n in graph["nodes"]}
    taken = set(zip(path[:step], path[1:step + 1]))
    ahead = set(zip(path[step:], path[step + 1:]))
    current = path[step]
    compromised = set(path[1:step])

    lines = [
        "digraph G {",
        '  rankdir=LR; bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11];',
    ]
    for node_id, name in names.items():
        if node_id == current and step > 0:
            attrs = 'fillcolor="#dc2626", fontcolor="white", color="#7f1d1d", penwidth=3'
            label = f"{name}\\n(attacker is here)"
        elif node_id == current:
            attrs = 'fillcolor="#fde68a", color="#b45309", penwidth=3'
            label = f"{name}\\n(attacker)"
        elif node_id in compromised:
            attrs = 'fillcolor="#fecaca", color="#dc2626"'
            label = f"{name}\\n(compromised)"
        elif node_id == path[-1]:
            attrs = 'fillcolor="#fff7ed", color="#ea580c", penwidth=2'
            label = f"{name}\\n(target)"
        else:
            attrs = 'fillcolor="#eff6ff", color="#93c5fd"'
            label = name
        lines.append(f'  "{node_id}" [label="{label}", {attrs}];')
    for edge in graph["edges"]:
        u, v = edge["source"], edge["target"]
        if (u, v) in taken:
            attrs = 'color="#dc2626", penwidth=3'
        elif (u, v) in ahead:
            attrs = 'color="#fca5a5", style=dashed, penwidth=2'
        else:
            attrs = 'color="#94a3b8"'
        lines.append(f'  "{u}" -> "{v}" [{attrs}];')
    lines.append("}")
    return "\n".join(lines)


def _draw(slot, graph, path, steps, step):
    info = steps[step]
    total = steps[-1]["effort"] or 1
    with slot.container():
        st.progress(step / (len(steps) - 1), text=f"Step {step} of {len(steps) - 1}")
        box = st.error if step == len(steps) - 1 else (st.warning if step else st.info)
        box(f"**{info['title']}**\n\n{info['text']}")
        st.graphviz_chart(_dot(graph, path, step))
        st.caption(f"Attacker effort used so far: {info['effort']} of {total} "
                   "(red = route taken · dashed pink = route still ahead)")


def render_attack_replay(graph, path, key="replay", title="▶️ Watch the attack, step by step"):
    """Replay controls (restart, back, next, auto-play) for one attack path."""
    if not path or len(path) < 2:
        return
    steps = _steps(graph, path)
    state_key = f"{key}_step"
    if st.session_state.get(f"{key}_path") != path:
        st.session_state[f"{key}_path"] = path
        st.session_state[state_key] = 0
    step = st.session_state.setdefault(state_key, 0)
    last = len(steps) - 1

    st.subheader(title)
    st.caption("See how a hacker could move through the network, one break-in at a time.")
    c1, c2, c3, c4 = st.columns(4)
    restart = c1.button("⏮ Restart", key=f"{key}_restart", width="stretch")
    back = c2.button("◀ Back", key=f"{key}_back", width="stretch", disabled=step == 0)
    nxt = c3.button("Next ▶", key=f"{key}_next", width="stretch", disabled=step == last)
    play = c4.button("⏯ Play all", key=f"{key}_play", width="stretch", type="primary")

    if restart:
        step = 0
    elif back:
        step = max(0, step - 1)
    elif nxt:
        step = min(last, step + 1)

    slot = st.empty()
    if play:
        for s in range(0, last + 1):
            _draw(slot, graph, path, steps, s)
            if s < last:
                time.sleep(1.6)
        step = last
    else:
        _draw(slot, graph, path, steps, step)
    st.session_state[state_key] = step

    if step == last:
        first_hop = steps[1]["title"].split("the ", 1)[-1]
        st.success(
            f"🛡️ **How to stop it:** the attack needed {last} break-ins. Fixing the weakness used in "
            f"step 1 (the {first_hop}) makes the very first step harder. Try it in the "
            "**Security Action Simulator** on the Defense Verification page."
        )


def render_baseline_attack_replay():
    """Replay of today's easiest attack route (INTERNET -> DB01)."""
    from src.astar_search import astar_search
    from src.graph_builder import build_graph

    graph = build_graph()
    render_attack_replay(graph, astar_search(graph)["path"], key="baseline_replay")

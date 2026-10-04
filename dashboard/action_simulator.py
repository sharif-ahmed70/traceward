"""Security Action Simulator: a plain-language what-if page for non-technical users.

The user builds a small plan (fix weaknesses, cut a connection, disconnect a server),
and the page re-runs A* to show whether an attacker can still reach the target.
"""

import streamlit as st

from src.astar_search import enumerate_attack_paths
from src.graph_builder import build_graph
from dashboard.attack_replay import render_attack_replay
from src.what_if_simulation import describe_action, find_chokepoints, simulate_actions

START, GOAL = "INTERNET", "DB01"

OUTCOME_STYLE = {
    "blocked": ("#16a34a", "✅"),
    "rerouted": ("#2563eb", "↪️"),
    "harder": ("#d97706", "🐢"),
    "unchanged": ("#6b7280", "➖"),
}


@st.cache_data
def _load_graph():
    return build_graph()


def _names(graph):
    return {n["id"]: n.get("name", n["id"]) for n in graph["nodes"]}


def _label(names, node_id):
    return f"{names[node_id]} ({node_id})"


def _difficulty(ease):
    if ease >= 0.7:
        return "easy to attack"
    if ease >= 0.4:
        return "medium"
    return "hard to attack"


def _graph_dot(graph, names, before_path, after_path, actions):
    """Network picture: red = today's attack route, orange = route after the plan."""
    isolated = {a["system"] for a in actions if a["type"] == "isolate"}
    blocked = {(a["source"], a["target"]) for a in actions if a["type"] == "block"}
    patched = {a["system"] for a in actions if a["type"] == "patch"}
    before_edges = set(zip(before_path, before_path[1:]))
    after_edges = set(zip(after_path, after_path[1:])) if after_path else set()

    lines = [
        "digraph G {",
        '  rankdir=LR; bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11];',
        '  edge [fontname="Helvetica", fontsize=9];',
    ]
    for node_id, name in names.items():
        if node_id in isolated:
            lines.append(f'  "{node_id}" [label="{name}\\n(disconnected)", fillcolor="#e5e7eb", fontcolor="#6b7280", style="rounded,filled,dashed"];')
        elif node_id == GOAL:
            lines.append(f'  "{node_id}" [label="{name}\\n(target)", fillcolor="#fee2e2", color="#dc2626"];')
        elif node_id == START:
            lines.append(f'  "{node_id}" [label="{name}\\n(attacker)", fillcolor="#f3f4f6"];')
        elif node_id in patched:
            lines.append(f'  "{node_id}" [label="{name}\\n(patched)", fillcolor="#dcfce7", color="#16a34a"];')
        else:
            lines.append(f'  "{node_id}" [label="{name}", fillcolor="#eff6ff", color="#93c5fd"];')

    for edge in graph["edges"]:
        u, v = edge["source"], edge["target"]
        if (u, v) in blocked:
            style = 'color="#9ca3af", style=dashed, label="cut"'
        elif (u, v) in after_edges:
            style = 'color="#ea580c", penwidth=3'
        elif (u, v) in before_edges:
            style = 'color="#dc2626", penwidth=2, style=dashed' if after_path is not None or isolated or blocked else 'color="#dc2626", penwidth=3'
        else:
            style = 'color="#94a3b8"'
        lines.append(f'  "{u}" -> "{v}" [{style}];')
    lines.append("}")
    return "\n".join(lines)


def _add(action):
    plan = st.session_state.setdefault("sim_plan", [])
    if action not in plan:
        plan.append(action)


def render_action_simulator():
    graph = _load_graph()
    names = _names(graph)
    hosts = [n for n in names if n not in (START, GOAL)]
    plan = st.session_state.setdefault("sim_plan", [])

    st.header("🛡️ Security Action Simulator")
    st.markdown(
        "Try a security fix **before** doing it for real. Pick one or more actions, press "
        f"**Run simulation**, and see whether a hacker on the internet could still reach the "
        f"**{names[GOAL]}**, where the most sensitive data is kept."
    )

    # --- Today's situation ------------------------------------------------------------
    routes = enumerate_attack_paths(graph, START, GOAL)
    easiest = " → ".join(names[n] for n in routes[0]["path"])
    chokepoints = find_chokepoints(graph, START, GOAL)

    c1, c2 = st.columns(2)
    c1.metric("Possible attack routes today", len(routes))
    c2.metric("Easiest route length", f"{len(routes[0]['path']) - 1} steps")
    st.error(f"**Easiest attack route today:** {easiest}")
    if chokepoints["hosts"]:
        weak = ", ".join(names[h] for h in chokepoints["hosts"])
        st.warning(
            f"🎯 **Weak point found:** every attack route passes through the **{weak}**. "
            "Protecting it well would stop all of these attacks."
        )

    # --- Quick examples ---------------------------------------------------------------
    st.subheader("Step 1: Choose what to try")
    st.caption("New here? Start with a ready-made example:")
    e1, e2, e3 = st.columns(3)
    if e1.button("Fix all weaknesses on the Web Server", width="stretch"):
        st.session_state.sim_plan = [{"type": "patch", "system": "WEB01",
                                      "vuln_ids": list(graph["vuln_ease_map"].get("WEB01", {}))}]
        st.rerun()
    if e2.button("Cut Web Server → Application Server", width="stretch"):
        st.session_state.sim_plan = [{"type": "block", "source": "WEB01", "target": "APP01"}]
        st.rerun()
    if e3.button("Disconnect the Application Server", width="stretch"):
        st.session_state.sim_plan = [{"type": "isolate", "system": "APP01"}]
        st.rerun()

    st.caption("Or build your own plan. You can combine several actions:")
    tab_fix, tab_cut, tab_off = st.tabs([
        "🩹 Fix weaknesses on a server",
        "✂️ Cut a connection",
        "🚫 Disconnect a server",
    ])

    with tab_fix:
        st.caption("Installing security updates (patches) removes weaknesses an attacker could use.")
        server = st.selectbox("Which server?", hosts, format_func=lambda n: _label(names, n), key="fix_server")
        eases = graph["vuln_ease_map"].get(server, {})
        ranked = sorted(eases, key=lambda v: (-eases[v], v))
        how = st.radio(
            "How many weaknesses?",
            ["The 10 most dangerous", "All of them", "Let me choose"],
            horizontal=True,
            key="fix_how",
        )
        if how == "The 10 most dangerous":
            chosen = ranked[:10]
        elif how == "All of them":
            chosen = ranked
        else:
            chosen = st.multiselect(
                "Pick the weaknesses to fix (most dangerous first)",
                ranked,
                format_func=lambda v: f"{v}: {_difficulty(eases[v])}",
                key="fix_pick",
            )
        st.caption(f"This server has {len(eases)} known weaknesses; you selected {len(chosen)}.")
        if st.button("➕ Add to plan", key="add_fix", disabled=not chosen):
            _add({"type": "patch", "system": server, "vuln_ids": list(chosen)})
            st.rerun()

    with tab_cut:
        st.caption("A firewall rule can stop one server from talking to another.")
        connections = [(e["source"], e["target"]) for e in graph["edges"]]
        conn = st.selectbox(
            "Which connection?",
            connections,
            format_func=lambda c: f"{names[c[0]]} → {names[c[1]]}",
            key="cut_conn",
        )
        if st.button("➕ Add to plan", key="add_cut"):
            _add({"type": "block", "source": conn[0], "target": conn[1]})
            st.rerun()

    with tab_off:
        st.caption("Taking a server off the network stops attacks through it, but also stops its normal work.")
        server_off = st.selectbox("Which server?", hosts, format_func=lambda n: _label(names, n), key="off_server")
        if st.button("➕ Add to plan", key="add_off"):
            _add({"type": "isolate", "system": server_off})
            st.rerun()

    # --- Plan ---------------------------------------------------------------------------
    st.subheader("Step 2: Your plan")
    if not plan:
        st.info("Your plan is empty. Add an action above or click an example.")
        _render_glossary()
        return

    for i, action in enumerate(plan):
        a, b = st.columns([6, 1])
        a.write(f"{i + 1}. {describe_action(graph, action)}")
        if b.button("✕", key=f"rm_{i}", help="Remove this action"):
            plan.pop(i)
            st.rerun()
    if st.button("🗑️ Clear plan"):
        st.session_state.sim_plan = []
        st.rerun()

    # --- Result -------------------------------------------------------------------------
    st.subheader("Step 3: Result")
    result = simulate_actions(plan, graph, START, GOAL)
    color, icon = OUTCOME_STYLE[result["outcome"]]
    st.markdown(
        f"""<div style="border-left: 6px solid {color}; background: {color}14; padding: 0.9rem 1.1rem;
        border-radius: 8px; margin-bottom: 0.8rem;">
        <div style="font-size: 1.25rem; font-weight: 700; color: {color};">{icon} {result['headline']}</div>
        <div style="margin-top: 0.35rem;">{result['explanation']}</div></div>""",
        unsafe_allow_html=True,
    )

    m1, m2 = st.columns(2)
    m1.metric(
        "Attack routes left",
        result["routes_after"],
        delta=result["routes_after"] - result["routes_before"],
        delta_color="inverse",
    )
    if result["effort_change_pct"] is None:
        m2.metric("Attacker effort", "Impossible", help="No route to the target remains.")
    else:
        m2.metric("Attacker effort", f"{result['effort_change_pct']:+.1f}%",
                  help="How much more work the easiest attack now takes. Higher is better for you.")

    b1, b2 = st.columns(2)
    b1.markdown(f"**Before:** {result['baseline']['path_names']}")
    b2.markdown(f"**After:** {result['simulated']['path_names'] or 'No route to the target'}")

    st.graphviz_chart(_graph_dot(graph, names, result["baseline"]["path"], result["simulated"]["path"], plan))
    st.caption("Red dashed = today's attack route · Orange = attack route after your plan · "
               "Grey dashed = cut or disconnected · Green = patched server")

    if result["outcome"] == "rerouted":
        render_attack_replay(result["sim_graph"], result["simulated"]["path"], key="sim_replay",
                             title="▶️ Watch the attacker's new route")

    with st.expander("Technical details (A* attack cost)"):
        st.write(f"Before: cost {result['baseline']['cost']}  ·  After: cost {result['simulated']['cost']}")
        st.caption("Attack cost is computed by A* search from network accessibility, predicted risk "
                   "and how easy each server's weaknesses are to exploit. Higher cost means harder to attack.")

    _render_glossary()


def _render_glossary():
    with st.expander("📖 What do these words mean?"):
        st.markdown(
            "- **Attack route**: a chain of servers a hacker could break into, one after another, "
            "to reach the target.\n"
            "- **Weakness (vulnerability)**: a flaw in software that an attacker can exploit.\n"
            "- **Patch**: a security update that removes a weakness.\n"
            "- **Cut a connection**: a firewall rule that blocks one server from reaching another.\n"
            "- **Disconnect a server**: take it off the network entirely.\n"
            "- **Weak point**: a server every attack route must pass through.\n"
            "- **Attacker effort**: how hard the easiest attack is. A higher number is better for you."
        )

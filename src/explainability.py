"""Structured Explainability Engine for TraceWard.

Transforms raw model predictions, network topology metadata, and CVSS feature
vectors into human-verifiable, transparent explanations.

Features:
- Exploitability vs. Impact (CIA Triad) multi-factor attribution
- Asset criticality and network exposure contextualization
- Automated evidence-based risk factor generation
- Targeted, defensible cybersecurity mitigation recommendations
- 100% backward-compatible contracts for main.py, CSP, and dashboard
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


# ---------------------------------------------------------------------------
# Feature specifications & baseline references
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploit_probability",
]

# Human-readable labels for CVSS categorical values
FEATURE_VALUE_LABELS = {
    "attack_complexity": {0: "Low (Easy)", 1: "High (Specialized conditions)"},
    "privileges_required": {0: "None (Unauthenticated)", 1: "Low (User)", 2: "High (Admin)"},
    "user_interaction": {0: "None (Autonomous)", 1: "Required (Victim action)"},
    "confidentiality_impact": {0: "None", 1: "Low", 2: "High"},
    "integrity_impact": {0: "None", 1: "Low", 2: "High"},
    "availability_impact": {0: "None", 1: "Low", 2: "High"},
}

CRITICALITY_LABELS = {
    5: "Crown Jewel (Level 5/5)",
    4: "Mission-Critical (Level 4/5)",
    3: "Operational Asset (Level 3/5)",
    2: "Internal Client (Level 2/5)",
    1: "External / Untrusted (Level 1/5)",
}


# ---------------------------------------------------------------------------
# Cached Network & Dataset Lookups
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _load_network_nodes(network_path: str = "data/network/network.json") -> Dict[str, Dict[str, Any]]:
    """Load and index network nodes from network.json."""
    p = Path(network_path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        nodes = data.get("nodes", [])
        return {node["id"]: node for node in nodes if "id" in node}
    except Exception:
        return {}


@functools.lru_cache(maxsize=1)
def _load_processed_vulnerabilities(dataset_path: str = "data/processed/vulnerabilities_processed.csv") -> Dict[str, Dict[str, Any]]:
    """Index processed vulnerability records by vuln_id for fast feature retrieval."""
    p = Path(dataset_path)
    if not p.exists():
        return {}
    try:
        import pandas as pd
        df = pd.read_csv(p)
        result = {}
        for _, row in df.iterrows():
            result[str(row["vuln_id"])] = {
                "system_id": str(row.get("system_id", "")),
                "attack_complexity": float(row.get("attack_complexity", 0)),
                "privileges_required": float(row.get("privileges_required", 0)),
                "user_interaction": float(row.get("user_interaction", 0)),
                "confidentiality_impact": float(row.get("confidentiality_impact", 0)),
                "integrity_impact": float(row.get("integrity_impact", 0)),
                "availability_impact": float(row.get("availability_impact", 0)),
                "exploit_probability": float(row.get("exploit_probability", 0.5)),
                "risk_label": str(row.get("risk_label", "")),
            }
        return result
    except Exception:
        return {}


@functools.lru_cache(maxsize=1)
def _load_system_risk_summary(risk_summary_path: str = "artifacts/risk/system_risk_summary.csv") -> Dict[str, Dict[str, Any]]:
    """Index system risk summary metrics by system_id."""
    p = Path(risk_summary_path)
    if not p.exists():
        return {}
    try:
        import pandas as pd
        df = pd.read_csv(p)
        result = {}
        for _, row in df.iterrows():
            sys_id = str(row.get("system_id", ""))
            if sys_id:
                result[sys_id] = {
                    "system_id": sys_id,
                    "normalized_risk": float(row.get("normalized_risk", 0.5)),
                    "vulnerability_count": int(row.get("vulnerability_count", 0)),
                    "highest_risk": str(row.get("highest_risk", "Medium")),
                    "critical_count": int(row.get("critical_count", 0)),
                    "high_or_critical_count": int(row.get("high_or_critical_count", 0)),
                }
        return result
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Core Explainability Engine Components
# ---------------------------------------------------------------------------

def get_system_context(system_id: str, network_path: str = "data/network/network.json") -> Dict[str, Any]:
    """Extract contextual asset metadata for an enterprise host from network.json."""
    nodes = _load_network_nodes(network_path)
    node = nodes.get(system_id)
    if not node:
        return {
            "system_id": system_id,
            "name": f"Host {system_id}",
            "type": "Server",
            "criticality": 3,
            "criticality_label": "Operational Asset (Level 3/5)",
            "internet_exposed": False,
            "exposure_scope": "Internal (Isolated from direct Internet ingress)",
            "role_description": "General enterprise system.",
        }

    crit = int(node.get("criticality", 3))
    exposed = bool(node.get("internet_exposed", False))
    node_type = str(node.get("type", "Server"))
    name = str(node.get("name", system_id))

    exposure_scope = "Perimeter-Facing (Direct external ingress)" if exposed else "Internal (Lateral movement required)"

    role_desc = {
        "Database": "Stores confidential core business records and customer data.",
        "Server": "Executes application logic or infrastructure services.",
        "Gateway": "Secures enterprise network boundary and VPN ingress.",
        "Workstation": "End-user client endpoint.",
        "External": "Untrusted external network environment.",
    }.get(node_type, "Enterprise computing resource.")

    return {
        "system_id": system_id,
        "name": name,
        "type": node_type,
        "criticality": crit,
        "criticality_label": CRITICALITY_LABELS.get(crit, f"Level {crit}/5"),
        "internet_exposed": exposed,
        "exposure_scope": exposure_scope,
        "role_description": role_desc,
    }


def compute_feature_contributions(features: Dict[str, Any]) -> Dict[str, Any]:
    """Deconstruct the 7 security dimensions into Exploitability and CIA Impact subscores.

    Returns:
        Dict containing:
        - subscores: exploitability_score, impact_score, primary_driver
        - contributions: per-feature normalized scores, directions, and qualitative rationales
    """
    ac = float(features.get("attack_complexity", 0))
    pr = float(features.get("privileges_required", 0))
    ui = float(features.get("user_interaction", 0))
    ci = float(features.get("confidentiality_impact", 0))
    ii = float(features.get("integrity_impact", 0))
    ai = float(features.get("availability_impact", 0))
    ep = float(features.get("exploit_probability", 0.5))

    # Normalized risk directions (1.0 = maximum risk factor, 0.0 = minimal risk)
    norm_ac = 1.0 - min(1.0, max(0.0, ac))
    norm_pr = (2.0 - min(2.0, max(0.0, pr))) / 2.0
    norm_ui = 1.0 - min(1.0, max(0.0, ui))
    norm_ep = min(1.0, max(0.0, ep))

    norm_ci = min(2.0, max(0.0, ci)) / 2.0
    norm_ii = min(2.0, max(0.0, ii)) / 2.0
    norm_ai = min(2.0, max(0.0, ai)) / 2.0

    # Weighted Exploitability (Ease of attacker breach)
    exploitability_score = round(
        0.25 * norm_ac + 0.30 * norm_pr + 0.20 * norm_ui + 0.25 * norm_ep, 4
    )

    # Weighted Impact (Consequences of successful compromise)
    impact_score = round((norm_ci + norm_ii + norm_ai) / 3.0, 4)

    primary_driver = "Impact (CIA Triad)" if impact_score >= exploitability_score else "Exploitability (Attack Ease)"

    contributions = {
        "attack_complexity": {
            "value": ac,
            "display": FEATURE_VALUE_LABELS["attack_complexity"].get(int(ac), str(ac)),
            "normalized_risk": round(norm_ac, 2),
            "direction": "+Risk" if norm_ac >= 0.5 else "-Risk",
            "rationale": "Standard exploitation without specialized timing or protocol conditions."
            if norm_ac >= 0.5
            else "Requires specialized access conditions or timing windows.",
        },
        "privileges_required": {
            "value": pr,
            "display": FEATURE_VALUE_LABELS["privileges_required"].get(int(pr), str(pr)),
            "normalized_risk": round(norm_pr, 2),
            "direction": "+Risk" if norm_pr >= 0.5 else "-Risk",
            "rationale": "Unauthenticated remote execution: no credentials required."
            if pr == 0
            else ("Requires basic user authentication." if pr == 1 else "Requires elevated administrative privileges."),
        },
        "user_interaction": {
            "value": ui,
            "display": FEATURE_VALUE_LABELS["user_interaction"].get(int(ui), str(ui)),
            "normalized_risk": round(norm_ui, 2),
            "direction": "+Risk" if norm_ui >= 0.5 else "-Risk",
            "rationale": "Autonomous exploitation: no victim interaction needed."
            if ui == 0
            else "Requires victim interaction (e.g. clicking malicious link).",
        },
        "exploit_probability": {
            "value": ep,
            "display": f"{ep:.2f}",
            "normalized_risk": round(norm_ep, 2),
            "direction": "+Risk" if norm_ep >= 0.5 else "-Risk",
            "rationale": f"In-the-wild exploitation probability estimated at {ep * 100:.1f}%.",
        },
        "confidentiality_impact": {
            "value": ci,
            "display": FEATURE_VALUE_LABELS["confidentiality_impact"].get(int(ci), str(ci)),
            "normalized_risk": round(norm_ci, 2),
            "direction": "+Risk" if norm_ci >= 0.5 else "-Risk",
            "rationale": "Complete confidentiality breach: disclosure of all protected host records."
            if ci == 2
            else ("Partial data disclosure." if ci == 1 else "No confidentiality impact."),
        },
        "integrity_impact": {
            "value": ii,
            "display": FEATURE_VALUE_LABELS["integrity_impact"].get(int(ii), str(ii)),
            "normalized_risk": round(norm_ii, 2),
            "direction": "+Risk" if norm_ii >= 0.5 else "-Risk",
            "rationale": "Total compromise of system integrity: arbitrary modification of files/state."
            if ii == 2
            else ("Partial modification possible." if ii == 1 else "No integrity impact."),
        },
        "availability_impact": {
            "value": ai,
            "display": FEATURE_VALUE_LABELS["availability_impact"].get(int(ai), str(ai)),
            "normalized_risk": round(norm_ai, 2),
            "direction": "+Risk" if norm_ai >= 0.5 else "-Risk",
            "rationale": "Total denial of service: host shutdown or complete resource exhaustion."
            if ai == 2
            else ("Reduced performance or partial interruption." if ai == 1 else "No availability impact."),
        },
    }

    return {
        "subscores": {
            "exploitability_score": exploitability_score,
            "impact_score": impact_score,
            "primary_driver": primary_driver,
        },
        "contributions": contributions,
    }


def generate_risk_factors(
    features: Dict[str, Any],
    asset_context: Dict[str, Any],
    predicted_risk: str = "Medium",
) -> List[str]:
    """Generate concise, evidence-grounded risk factor bullets from feature attributes."""
    factors = []

    pr = int(features.get("privileges_required", 1))
    if pr == 0:
        factors.append("Unauthenticated Access: Attacker requires zero prior privileges (PR=None).")
    elif pr == 1:
        factors.append("User-Level Authentication: Requires standard user credentials (PR=Low).")

    ac = int(features.get("attack_complexity", 0))
    if ac == 0:
        factors.append("Low Attack Complexity: Standardized exploitation without specialized conditions.")

    ui = int(features.get("user_interaction", 0))
    if ui == 0:
        factors.append("Autonomous Exploitation: Executes without victim interaction (UI=None).")

    ep = float(features.get("exploit_probability", 0.5))
    if ep >= 0.60:
        factors.append(f"High Exploit Probability ({ep:.2f}): Significant likelihood of active weaponization.")

    ci = int(features.get("confidentiality_impact", 0))
    if ci == 2:
        factors.append("High Confidentiality Loss: Potential extraction of sensitive system records.")

    ii = int(features.get("integrity_impact", 0))
    if ii == 2:
        factors.append("High Integrity Breach: Full capability to tamper with system state or data.")

    ai = int(features.get("availability_impact", 0))
    if ai == 2:
        factors.append("High Availability Denial: Potential service outage or total resource exhaustion.")

    # Contextual host factor
    crit = int(asset_context.get("criticality", 3))
    host_name = asset_context.get("name", asset_context.get("system_id", "Host"))
    if crit >= 5:
        factors.append(f"Crown-Jewel Asset: Located on {host_name} (Criticality Level 5/5).")
    elif asset_context.get("internet_exposed", False):
        factors.append(f"Perimeter Exposure: {host_name} has direct ingress from the Internet.")

    if not factors:
        factors.append(f"Standard operational profile consistent with {predicted_risk} risk baseline.")

    return factors


def generate_recommended_action(
    predicted_risk: str,
    asset_context: Dict[str, Any],
    subscores: Dict[str, float],
) -> str:
    """Generate targeted, actionable cybersecurity remediation guidance."""
    crit = int(asset_context.get("criticality", 3))
    exposed = bool(asset_context.get("internet_exposed", False))

    if predicted_risk == "Critical":
        if crit >= 5:
            return (
                "Emergency Remediation (Within 24h): Apply vendor security patch or deploy compensating "
                "network controls immediately. Restrict internal access to host, isolate ingress service port, "
                "and inspect audit logs for indicators of active compromise."
            )
        elif exposed:
            return (
                "Perimeter Lockdown: Apply emergency virtual patch at Web Application Firewall (WAF) / Gateway. "
                "Schedule binary patch within 48 hours and restrict source IP ranges where possible."
            )
        else:
            return (
                "Critical Priority Remediation: Schedule patch application within 48 hours. Enforce strict firewall "
                "segmentation between application tiers to contain lateral movement."
            )
    elif predicted_risk == "High":
        if exposed:
            return (
                "Priority Perimeter Defense: Update firewall rules to filter anomalous requests to the target port. "
                "Queue software patch for immediate deployment in the next operational cycle."
            )
        else:
            return (
                "High-Priority Patching: Schedule software update in the next scheduled maintenance window (within 7 days). "
                "Verify database access controls and audit user privilege assignments."
            )
    elif predicted_risk == "Medium":
        return (
            "Scheduled Mitigation: Include remediation in standard bi-weekly patch cycle. Maintain continuous "
            "monitoring on service endpoints and ensure automated backups are current."
        )
    else:  # Low
        return (
            "Routine Maintenance: Remediate during standard quarterly patching or scheduled system overhauls. "
            "No immediate containment required."
        )


# ---------------------------------------------------------------------------
# High-Level Explanation API (Backward Compatible)
# ---------------------------------------------------------------------------

def explain_vulnerability(
    vuln_id: str,
    system_id: Optional[str] = None,
    predicted_risk: Optional[str] = None,
    *,
    features: Optional[Dict[str, Any]] = None,
    cluster_id: Optional[int] = None,
    vote_share: Optional[float] = None,
    network_path: str = "data/network/network.json",
    dataset_path: str = "data/processed/vulnerabilities_processed.csv",
) -> Dict[str, Any]:
    """Build a comprehensive, transparent explanation for a vulnerability risk prediction.

    Combines:
    - Feature-level Exploitability and Impact (CIA) attribution
    - Asset criticality context from network.json
    - Evidence-based risk factor bullets
    - Actionable remediation advice
    """
    resolved_features: Dict[str, Any] = {}
    stored_vulnerabilities = _load_processed_vulnerabilities(dataset_path)

    if features is not None:
        resolved_features = dict(features)
    elif vuln_id in stored_vulnerabilities:
        resolved_features = stored_vulnerabilities[vuln_id]
        if system_id is None:
            system_id = resolved_features.get("system_id", "UNKNOWN")
        if predicted_risk is None:
            predicted_risk = resolved_features.get("risk_label", "Medium")
    else:
        resolved_features = {
            "attack_complexity": 0,
            "privileges_required": 1,
            "user_interaction": 0,
            "confidentiality_impact": 1,
            "integrity_impact": 1,
            "availability_impact": 1,
            "exploit_probability": 0.5,
        }

    sys_id = system_id or "UNKNOWN"
    risk_level = predicted_risk or "Medium"

    asset_ctx = get_system_context(sys_id, network_path=network_path)
    contrib_res = compute_feature_contributions(resolved_features)
    subscores = contrib_res["subscores"]
    feature_contributions = contrib_res["contributions"]

    risk_factors = generate_risk_factors(resolved_features, asset_ctx, risk_level)
    action = generate_recommended_action(risk_level, asset_ctx, subscores)

    factor_text = "; ".join(risk_factors)
    cluster_text = (
        f"The vulnerability belongs to cluster {cluster_id}; cluster membership is descriptive, not a risk label."
        if cluster_id is not None
        else "No clustering result supplied yet."
    )

    vote_text = f" (KNN neighbor vote share: {vote_share:.3f})" if vote_share is not None else ""
    summary_text = (
        f"Predicted risk for {vuln_id} on {sys_id}: {risk_level}{vote_text}. "
        f"Primary driver: {subscores['primary_driver']} "
        f"(Exploitability={subscores['exploitability_score']:.2f}, Impact={subscores['impact_score']:.2f})."
    )

    human_readable_text = (
        f"{factor_text} Asset status: {asset_ctx['name']} ({asset_ctx['criticality_label']}, {asset_ctx['exposure_scope']}). "
        f"Recommended Action: {action}"
    )

    return {
        "vulnerability_id": vuln_id,
        "vuln_id": vuln_id,
        "system_id": sys_id,
        "predicted_risk": risk_level,
        "decision": risk_level,
        "risk_factors": risk_factors,
        "evidence": risk_factors,
        "feature_contributions": feature_contributions,
        "subscores": subscores,
        "asset_context": asset_ctx,
        "recommended_action": action,
        "cluster_context": cluster_text,
        "vote_share": vote_share,
        "summary": summary_text,
        "human_readable": human_readable_text,
    }


def explain_risk(
    vuln_id: str,
    system_id: str,
    predicted_risk: str,
    *,
    risk_factors: Optional[Iterable[str]] = None,
    cluster_id: Optional[int] = None,
    features: Optional[Dict[str, Any]] = None,
    vote_share: Optional[float] = None,
) -> Dict[str, Any]:
    """Backward-compatible entry point for risk explanation."""
    res = explain_vulnerability(
        vuln_id=vuln_id,
        system_id=system_id,
        predicted_risk=predicted_risk,
        features=features,
        cluster_id=cluster_id,
        vote_share=vote_share,
    )

    if risk_factors:
        custom_factors = list(risk_factors)
        combined_factors = custom_factors + [f for f in res["risk_factors"] if f not in custom_factors]
        res["risk_factors"] = combined_factors
        res["evidence"] = combined_factors

    return res


def explain_attack_path(
    start_node: str,
    goal_node: str,
    path: List[str],
    total_cost: Optional[float] = None,
    network_path: str = "data/network/network.json",
    risk_summary_path: str = "artifacts/risk/system_risk_summary.csv",
) -> Dict[str, Any]:
    """Explain the selected A* attack path with structured intelligence and risk attribution.

    Returns:
        Dict containing:
        - Legacy keys: type, start, goal, path, total_cost, summary, human_readable
        - Enriched structured keys:
          - entry_point, target_asset, hop_count
          - path_nodes: node-by-node details with kill-chain phase, step cost, risk reason
          - attack_logic: adversary optimization rationale
          - business_impact: asset exposure and operational consequence
    """
    path_list = list(path) if path else []
    hop_count = max(0, len(path_list) - 1) if path_list else 0

    risk_data = _load_system_risk_summary(risk_summary_path)
    path_nodes = []
    cumulative_cost = 0.0

    for i, node_id in enumerate(path_list):
        node_ctx = get_system_context(node_id, network_path=network_path)
        sys_risk = risk_data.get(node_id, {})
        norm_risk = sys_risk.get("normalized_risk", 0.25 if node_id == "INTERNET" else 0.5)
        highest_risk = sys_risk.get("highest_risk", "Critical" if norm_risk >= 0.6 else "Medium")
        vuln_count = sys_risk.get("vulnerability_count", 0)

        # Step cost calculation matching A* cost metric: max(0.5, round(2.0 - norm_risk, 2))
        if i == 0:
            step_cost = 0.0
        else:
            step_cost = max(0.5, round(2.0 - norm_risk, 2))
            cumulative_cost += step_cost

        # Determine Cyber Kill Chain phase and threat context
        if i == 0:
            phase = "Perimeter Ingress & External Exposure"
            role = "Untrusted Public Network"
            risk_reason = "Untrusted external network perimeter initiating adversary reconnaissance and breach vectors."
        elif i == 1:
            phase = "Initial Foothold & Perimeter Compromise"
            role = node_ctx.get("role_description", "Perimeter-facing server")
            risk_reason = (
                f"Perimeter-exposed host with elevated vulnerability density ({vuln_count} flaws). "
                f"Low traversal resistance (step cost {step_cost:.2f}) enables immediate foothold."
            )
        elif i == len(path_list) - 1:
            phase = "Crown Jewel & Exfiltration Target"
            role = node_ctx.get("role_description", "Core internal asset")
            risk_reason = (
                f"Primary adversary objective holding mission-critical data ({node_ctx.get('criticality_label')}). "
                "Target reached via application-tier exploitation."
            )
        else:
            phase = "Lateral Movement & Privilege Pivoting"
            role = node_ctx.get("role_description", "Internal tier component")
            risk_reason = (
                f"Internal pivot host bridging perimeter to sensitive enterprise segments. "
                f"Vulnerability density allows lateral hopping with step cost {step_cost:.2f}."
            )

        path_nodes.append({
            "node_id": node_id,
            "name": node_ctx.get("name", node_id),
            "type": node_ctx.get("type", "Server"),
            "role": role,
            "criticality": node_ctx.get("criticality", 3),
            "criticality_label": node_ctx.get("criticality_label", "Level 3/5"),
            "internet_exposed": node_ctx.get("internet_exposed", False),
            "phase": phase,
            "step_cost": step_cost,
            "cumulative_cost": round(cumulative_cost, 2),
            "risk_score": norm_risk,
            "risk_level": highest_risk,
            "risk_reason": risk_reason,
            "vulnerability_count": vuln_count,
        })

    resolved_cost = total_cost if total_cost is not None else (round(cumulative_cost, 2) if cumulative_cost > 0 else None)

    # Adversary path optimization logic
    attack_logic = (
        "Adversary corridor computed via A* heuristic search over risk-weighted edge impedances "
        r"($c(u,v) = \max(0.5, 2.0 - \text{Risk}(v))$). Nodes exhibiting higher vulnerability density "
        "impose lower traversal impedance, establishing this path as the path of least resistance "
        "from external ingress to internal enterprise assets."
    )

    # Business impact analysis
    goal_ctx = get_system_context(goal_node, network_path=network_path)
    business_impact = (
        f"Critical breach corridor culminates at {goal_ctx.get('name', goal_node)} "
        f"({goal_node}, {goal_ctx.get('criticality_label')}). Unauthorized access risks "
        "unrestricted data exfiltration, database tampering, and regulatory compliance violations "
        "across core enterprise operations."
    )

    path_text = " -> ".join(path_list) if path_list else "No path selected."
    cost_text = f" Total path cost: {resolved_cost:g}." if resolved_cost is not None else ""
    summary_text = (
        f"Risk-aware analysis identified a {hop_count}-hop critical breach corridor ({path_text}).{cost_text}"
        if path_list
        else "No path selected."
    )
    human_readable_text = (
        "This simulated breach corridor is derived from A* graph traversal over risk-weighted friction metrics; "
        "it serves defensive prioritization and attack-surface reduction."
    )

    return {
        "type": "attack_path",
        "start": start_node,
        "goal": goal_node,
        "path": path_list,
        "total_cost": resolved_cost,
        "summary": summary_text,
        "human_readable": human_readable_text,
        "entry_point": start_node,
        "target_asset": goal_node,
        "hop_count": hop_count,
        "path_nodes": path_nodes,
        "attack_logic": attack_logic,
        "business_impact": business_impact,
    }


def explain_patch_priority(
    vuln_id: str,
    system_id: str,
    priority: str,
    *,
    reason: Optional[str] = None,
    scheduled_slot: Optional[str] = None,
    team: Optional[str] = None,
) -> Dict[str, Any]:
    """Explain why a remediation task has its priority and schedule."""
    reason_text = reason or "Priority supplied by the upstream risk-analysis contract."
    schedule_text = (
        f"Scheduled for {scheduled_slot} with {team}." if scheduled_slot and team else "Schedule not assigned yet."
    )
    return {
        "type": "patch_priority",
        "vuln_id": vuln_id,
        "system_id": system_id,
        "priority": priority,
        "reason": reason_text,
        "scheduled_slot": scheduled_slot,
        "team": team,
        "summary": f"{vuln_id} on {system_id} is marked {priority}. {reason_text} {schedule_text}",
    }


def build_explanation_report(
    *,
    risk: Optional[Dict[str, Any]] = None,
    attack_path: Optional[Dict[str, Any]] = None,
    patch_priority: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Combine available explanations into one dashboard-friendly structure."""
    sections = {}
    if risk:
        sections["risk"] = risk
    if attack_path:
        sections["attack_path"] = attack_path
    if patch_priority:
        sections["patch_priority"] = patch_priority
    return {"sections": sections}


def main() -> None:
    exp = explain_vulnerability("V1136", "DB01", "Critical")
    print("Structured Explanation Sample:")
    print(f"Summary: {exp['summary']}")
    print(f"Action:  {exp['recommended_action']}")


if __name__ == "__main__":
    main()

"""Human-readable explanations for TraceWard model and planning outputs.

Week 1 uses structured explanations so later K-Means, KNN and A* outputs can
be connected without changing the dashboard interface.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


def explain_risk(
    vuln_id: str,
    system_id: str,
    predicted_risk: str,
    *,
    risk_factors: Optional[Iterable[str]] = None,
    cluster_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Build a transparent explanation for a vulnerability risk prediction."""
    factors = list(risk_factors or [])
    factor_text = "; ".join(factors) if factors else "No feature-level explanation supplied yet."
    cluster_text = (
        f"The vulnerability belongs to cluster {cluster_id}; cluster membership is descriptive, not a risk label."
        if cluster_id is not None
        else "No clustering result supplied yet."
    )

    return {
        "type": "risk",
        "vuln_id": vuln_id,
        "system_id": system_id,
        "decision": predicted_risk,
        "summary": f"Predicted risk for {vuln_id} on {system_id}: {predicted_risk}.",
        "evidence": factors,
        "cluster_context": cluster_text,
        "human_readable": f"{factor_text} {cluster_text}",
    }


def explain_attack_path(
    start_node: str,
    goal_node: str,
    path: List[str],
    total_cost: Optional[float] = None,
) -> Dict[str, Any]:
    """Explain the selected A* path without claiming it is an actual attack."""
    path_text = " -> ".join(path) if path else "No path selected."
    cost_text = f" Total path cost: {total_cost:g}." if total_cost is not None else ""
    return {
        "type": "attack_path",
        "start": start_node,
        "goal": goal_node,
        "path": path,
        "total_cost": total_cost,
        "summary": f"Risk-aware analysis selected the simulated route {path_text}.{cost_text}",
        "human_readable": (
            "This is a simulated network path for defensive risk analysis; it does not represent "
            "an exploitation procedure."
        ),
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
    report = build_explanation_report(
        risk=explain_risk(
            "VULN-001",
            "WEB01",
            "Critical",
            risk_factors=["High severity input feature", "Exposed web-facing system"],
            cluster_id=2,
        ),
        attack_path=explain_attack_path(
            "INTERNET", "DB01", ["INTERNET", "WEB01", "APP01", "DB01"], 8.5
        ),
        patch_priority=explain_patch_priority(
            "VULN-001",
            "WEB01",
            "Critical",
            reason="Highest-priority mock risk item in the review case.",
            scheduled_slot="Mon 09:00",
            team="Web Team",
        ),
    )
    print(report)


if __name__ == "__main__":
    main()

"""Unified FinBank simulation service.

Provides a deterministic end-to-end simulation pipeline for a given FinBank
scenario_id, producing a structured SimulationResult containing the full
simulation output across all pipeline stages.

Pipeline stages:
    1. FinBank environment
    2. Vulnerability inventory
    3. Attack simulator
    4. Incident correlation
    5. KNN risk analysis
    6. System risk aggregation
    7. Simulated attack path (A*)
    8. CSP remediation plan
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from src.finbank_env import load_finbank_systems, validate_finbank_systems
from src.finbank_assignment import assign_finbank_vulnerabilities
from src.attack_simulator.simulator import simulate_finbank_attack
from src.incident_correlator import correlate_single_scenario, incident_to_dict
from src.attack_simulator.scenarios import get_finbank_scenario, scenario_to_dict
from src.knn_classifier import (
    load_data as load_knn_data,
    get_features_and_target,
    split_data,
    train_and_select_k,
    predict_and_export,
)
from src.risk_engine import build_system_risk_summary
from src.finbank_network import build_finbank_graph
from src.finbank_astar_integration import run_scenario_attack_path
from src.finbank_csp_planner import run_finbank_remediation_plan
from src.what_if_simulation import simulate_patch_impact


@dataclass(frozen=True)
class SimulationResult:
    """Structured result of a complete FinBank simulation run."""

    scenario: dict[str, object]
    events: list[dict[str, object]]
    incident: dict[str, object]
    affected_systems: list[str]
    related_vulnerabilities: list[str]
    predicted_risks: list[dict[str, object]]
    attack_path: dict[str, object]
    remediation_plan: dict[str, object]


ARTIFACTS_BASE = Path("artifacts/finbank")

SCENARIO_DIR = ARTIFACTS_BASE / "scenarios"
EVENTS_DIR = ARTIFACTS_BASE / "events"
INCIDENTS_DIR = ARTIFACTS_BASE / "incidents"
ATTACK_PATHS_DIR = ARTIFACTS_BASE / "attack_paths"
REMEDIATION_PLANS_DIR = ARTIFACTS_BASE / "remediation_plans"

ALL_SCENARIO_IDS = (
    "customer_portal_compromise",
    "employee_compromise",
    "remote_access_compromise",
    "backup_targeting",
)


def _ensure_dirs() -> None:
    for d in (
        SCENARIO_DIR,
        EVENTS_DIR,
        INCIDENTS_DIR,
        ATTACK_PATHS_DIR,
        REMEDIATION_PLANS_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)


def _save_scenario(scenario: dict[str, object], scenario_id: str) -> Path:
    p = SCENARIO_DIR / f"{scenario_id}.json"
    p.write_text(json.dumps(scenario, indent=2), encoding="utf-8")
    return p


def _save_events(events: list[dict[str, object]], scenario_id: str) -> Path:
    p = EVENTS_DIR / f"{scenario_id}.json"
    p.write_text(json.dumps(events, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _save_incident(incident: dict[str, object], scenario_id: str) -> Path:
    p = INCIDENTS_DIR / f"{scenario_id}.json"
    p.write_text(json.dumps(incident, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _save_attack_path(attack_path: dict[str, object], scenario_id: str) -> Path:
    p = ATTACK_PATHS_DIR / f"{scenario_id}.json"
    p.write_text(json.dumps(attack_path, indent=2, sort_keys=True), encoding="utf-8")
    return p


def _save_remediation_plan(
    remediation_plan: dict[str, object], scenario_id: str
) -> Path:
    p = REMEDIATION_PLANS_DIR / f"{scenario_id}.json"
    p.write_text(
        json.dumps(remediation_plan, indent=2, sort_keys=True), encoding="utf-8"
    )
    return p


def save_simulation_artifacts(
    result: SimulationResult, scenario_id: str
) -> dict[str, Path]:
    """Save simulation artifacts for a single scenario.

    Writes only to the FinBank artifact subdirectories and does not modify
    unrelated TraceWard artifacts.
    """
    _ensure_dirs()
    return {
        "scenario": _save_scenario(result.scenario, scenario_id),
        "events": _save_events(result.events, scenario_id),
        "incident": _save_incident(result.incident, scenario_id),
        "attack_path": _save_attack_path(result.attack_path, scenario_id),
        "remediation_plan": _save_remediation_plan(
            result.remediation_plan, scenario_id
        ),
    }


def run_finbank_simulation(
    scenario_id: str, save_artifacts: bool = False
) -> SimulationResult:
    """Execute the full FinBank simulation pipeline for a single scenario.

    Args:
        scenario_id: One of the deterministic FinBank scenario identifiers
            (e.g. ``customer_portal_compromise``, ``employee_compromise``,
            ``remote_access_compromise``, ``backup_targeting``).
        save_artifacts: If True, save simulation artifacts for this scenario.

    Returns:
        A frozen SimulationResult containing all pipeline outputs.
    """
    # 1. FinBank environment
    systems = load_finbank_systems()
    validate_finbank_systems(systems)

    # 2. Vulnerability inventory
    inventory = assign_finbank_vulnerabilities()

    # 3. Attack simulator
    events_df = simulate_finbank_attack(scenario_id, inventory=inventory)
    events = events_df.to_dict("records")

    # 4. Incident correlation
    incident = correlate_single_scenario(
        scenario_id, events_df, inventory, systems
    )
    incident_dict = incident_to_dict(incident)

    # 5. KNN risk analysis
    processed_path = Path("data/processed/vulnerabilities_processed.csv")
    knn_df = load_knn_data(str(processed_path))
    X, y, ids = get_features_and_target(knn_df)
    X_train, X_test, y_train, y_test, ids_train, ids_test = split_data(
        X, y, ids, test_size=0.2, random_state=42
    )
    model, _best_k = train_and_select_k(X_train, y_train, X_test, y_test)
    predictions = predict_and_export(model, X_test, y_test, ids_test)

    # 6. System risk aggregation
    build_system_risk_summary(
        input_path="artifacts/knn/predictions.csv",
        output_path="artifacts/risk/system_risk_summary.csv",
    )

    # 7. Simulated attack path (risk-weighted A*)
    graph = build_finbank_graph(
        network_path="data/finbank/network.json",
        risk_summary_path="artifacts/risk/system_risk_summary.csv",
    )
    attack_path_result = run_scenario_attack_path(
        scenario_id,
        graph=graph,
        include_vulnerabilities=False,
    )

    # 8. CSP remediation plan
    remediation_plan = run_finbank_remediation_plan(
        incident=incident,
        inventory=inventory,
        attack_path=attack_path_result["simulated_attack_path"],
        systems=systems,
    )

    result = SimulationResult(
        scenario=scenario_to_dict(get_finbank_scenario(scenario_id)),
        events=events,
        incident=incident_dict,
        affected_systems=list(incident.affected_systems),
        related_vulnerabilities=list(incident.related_vulnerabilities),
        predicted_risks=predictions.to_dict("records"),
        attack_path=attack_path_result,
        remediation_plan=remediation_plan,
    )

    if save_artifacts:
        save_simulation_artifacts(result, scenario_id)

    return result


def regenerate_all_finbank_artifacts(
    scenario_ids: tuple[str, ...] | None = None,
) -> dict[str, dict[str, Path]]:
    """Regenerate FinBank simulation artifacts deterministically.

    Args:
        scenario_ids: Optional tuple of scenario IDs. Defaults to all four.

    Returns:
        Mapping of scenario_id to saved artifact paths.
    """
    if scenario_ids is None:
        scenario_ids = ALL_SCENARIO_IDS

    saved: dict[str, dict[str, Path]] = {}
    for sid in scenario_ids:
        result = run_finbank_simulation(sid, save_artifacts=False)
        saved[sid] = save_simulation_artifacts(result, sid)
    return saved


def _print_demo(result: SimulationResult, what_if: dict[str, object]) -> None:
    """Print concise, human-readable demo output for a live presentation."""
    scenario = result.scenario
    incident = result.incident
    attack_path = result.attack_path
    remediation = result.remediation_plan

    print("=" * 60)
    print("TraceWard — FinBank Incident Simulation Demo")
    print("=" * 60)
    print()
    print(f"Scenario: {scenario.get('name', scenario.get('scenario_id'))}")
    print(f"Scenario ID: {scenario.get('scenario_id')}")
    print()

    print("[1/5] Simulated Attack Events")
    print("-" * 40)
    for idx, event in enumerate(result.events, start=1):
        event_type = event.get("event_type", "unknown").replace("_", " ").title()
        target = event.get("target", "—")
        description = event.get("description", "")
        print(f"  {idx}. {event_type} — {target}")
        if description:
            print(f"     {description}")
    print()

    print("[2/5] Incident Summary")
    print("-" * 40)
    print(f"  Incident ID: {incident.get('incident_id', '—')}")
    print(f"  Entry Point: {incident.get('entry_point', '—')}")
    print(f"  Affected Systems: {', '.join(result.affected_systems) if result.affected_systems else '—'}")
    print(f"  Related Vulnerabilities: {len(result.related_vulnerabilities)}")
    print(f"  Critical Assets Affected: {', '.join(incident.get('critical_assets_affected', [])) or '—'}")
    print()

    print("[3/5] Potential Attack Route")
    print("-" * 40)
    path = attack_path.get("simulated_attack_path", [])
    print(f"  Route: {' -> '.join(path) if path else '—'}")
    print(f"  Entry Point: {attack_path.get('entry_point', '—')}")
    print(f"  Target Asset: {attack_path.get('target_critical_asset', '—')}")
    print(f"  Route Length: {max(len(path) - 1, 0)} Hops")
    print()

    print("[4/5] Estimated Vulnerability Risk")
    print("-" * 40)
    high_or_critical = [
        p for p in result.predicted_risks if p.get("predicted_risk") in {"High", "Critical"}
    ]
    print(f"  Total Predictions: {len(result.predicted_risks)}")
    print(f"  High / Critical: {len(high_or_critical)}")
    for prediction in high_or_critical[:5]:
        print(f"    {prediction.get('vuln_id')} on {prediction.get('system_id')}: {prediction.get('predicted_risk')}")
    if len(high_or_critical) > 5:
        print(f"    ... and {len(high_or_critical) - 5} more")
    print()

    print("[5/5] Remediation Schedule")
    print("-" * 40)
    schedule = remediation.get("schedule", [])
    print(f"  Status: {remediation.get('status', 'unknown')}")
    print(f"  Scheduled Tasks: {len(schedule)}")
    for item in schedule[:5]:
        depends = item.get("depends_on", [])
        dep_str = f" [depends: {', '.join(depends)}]" if depends else ""
        print(f"    {item.get('vuln_id')} on {item.get('system_id')} ({item.get('priority')}) — {item.get('team')} @ {item.get('time_slot')}{dep_str}")
    if len(schedule) > 5:
        print(f"    ... and {len(schedule) - 5} more tasks")
    print()

    if what_if:
        print("[BONUS] Hypothetical What-If Simulation")
        print("-" * 40)
        baseline_risk = what_if["baseline"]["system_risk"]["normalized_risk"]
        simulated_risk = what_if["simulated"]["system_risk"]["normalized_risk"]
        baseline_path = what_if["baseline"]["attack_path"]
        simulated_path = what_if["simulated"]["attack_path"]
        risk_delta = what_if["deltas"]["risk_reduction"]
        cost_delta = what_if["deltas"]["path_cost_increase"]
        path_changed = what_if["deltas"]["path_diverted"]

        print(f"  Target System: {what_if.get('target_system', '—')}")
        print(f"  Simulated Risk Reduction: {what_if.get('risk_reduction_factor', 0.5):.0%}")
        print()
        print("  BEFORE:")
        print(f"    Estimated System Risk: {baseline_risk:.3f}")
        print(f"    Potential Attack Route: {' -> '.join(baseline_path)}")
        print()
        print("  AFTER:")
        print(f"    Estimated System Risk: {simulated_risk:.3f} (-{risk_delta:.3f})")
        if path_changed:
            print(f"    Potential Attack Route: Rerouted -> {' -> '.join(simulated_path)}")
        else:
            print(f"    Potential Attack Route: Maintained (Hardened)")
        print(f"    Route Difficulty Increase: +{cost_delta:.2f}")
        print()
        print(f"  Note: {what_if.get('explanation', '')}")
        print()

    print("=" * 60)
    print("Disclaimer:")
    print("The FinBank environment is fictional and the attacks are simulated.")
    print("No real systems are attacked or scanned.")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TraceWard FinBank simulation service.",
    )
    parser.add_argument(
        "--scenarios",
        nargs="*",
        choices=list(ALL_SCENARIO_IDS),
        help="Regenerate artifacts for the selected FinBank scenarios.",
    )
    parser.add_argument(
        "--demo",
        nargs="?",
        const="customer_portal_compromise",
        choices=list(ALL_SCENARIO_IDS),
        help="Run a single scenario end-to-end and print demo output.",
    )
    args = parser.parse_args()

    if args.demo:
        scenario_id = args.demo
        print(f"Running FinBank demo: {scenario_id}")
        result = run_finbank_simulation(scenario_id, save_artifacts=False)

        attack_path = result.attack_path.get("simulated_attack_path", ["INTERNET", "DB01"])
        try:
            what_if = simulate_patch_impact(
                target_system="WEB01",
                start_node=attack_path[0],
                goal_node=attack_path[-1],
            )
        except Exception as exc:
            print(f"What-if simulation failed: {exc}")
            what_if = {}

        _print_demo(result, what_if)
        return

    if args.scenarios:
        scenario_ids = tuple(args.scenarios)
        print("Regenerating FinBank simulation artifacts...")
        saved = regenerate_all_finbank_artifacts(scenario_ids=scenario_ids)
        for sid, paths in saved.items():
            print(f"\n[{sid}]")
            for name, path in paths.items():
                print(f"  {name}: {path}")
        print("\nDone.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

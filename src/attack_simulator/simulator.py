"""Fictional FinBank attack simulator.

Produces deterministic simulated attack event sequences from a FinBank
scenario and vulnerability inventory. No real attacks, network activity,
subprocesses, sockets, scanners, exploit frameworks, or payloads are used.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Optional

import pandas as pd

from src.attack_simulator.events import (
    EventType,
    AttackEvent,
    create_event,
    event_to_dict,
)
from src.attack_simulator.scenarios import AttackScenario, get_finbank_scenario

FIXED_SEED = 42
OUTPUT_PATH = Path("artifacts/finbank/simulated_events.csv")


def _select_vulnerability(
    target_system: str,
    inventory: pd.DataFrame,
    seed: int = FIXED_SEED,
) -> Optional[str]:
    candidates = inventory[inventory["system_id"] == target_system].copy()
    if candidates.empty:
        return None

    priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    candidates["_rank"] = candidates["risk_label"].map(lambda x: priority.get(x, 99))
    candidates = candidates.sort_values(by=["_rank", "vuln_id"])

    top = candidates.iloc[0]
    return str(top["vuln_id"])


def simulate_finbank_attack(
    scenario_id: str,
    inventory: Optional[pd.DataFrame] = None,
    inventory_path: str | Path = "artifacts/finbank/finbank_vulnerability_inventory.csv",
    seed: int = FIXED_SEED,
) -> pd.DataFrame:
    if inventory is None:
        p = Path(inventory_path)
        if not p.exists():
            raise FileNotFoundError(f"FinBank vulnerability inventory not found: {p}")
        inventory = pd.read_csv(p, keep_default_na=False)

    required_cols = {"vuln_id", "system_id", "risk_label"}
    missing = required_cols - set(inventory.columns)
    if missing:
        raise ValueError(f"Inventory missing required columns: {sorted(missing)}")

    scenario = get_finbank_scenario(scenario_id)
    events: list[AttackEvent] = []

    rng = random.Random(seed)

    current_source = scenario.entry_point
    first_target = scenario.target_systems[0]
    vuln_id = _select_vulnerability(first_target, inventory, seed=seed)

    initial = create_event(
        event_id=f"SIM-{scenario.scenario_id.upper()}-01",
        scenario_id=scenario.scenario_id,
        timestamp=1,
        source=current_source,
        target=first_target,
        event_type=EventType.INITIAL_ACCESS,
        vulnerability_id=vuln_id,
        severity="High",
        description=f"Simulated initial access from {current_source} to {first_target}.",
    )
    events.append(initial)

    previous_source = first_target
    step = 2
    for target in scenario.target_systems[1:]:
        vuln_id = _select_vulnerability(target, inventory, seed=seed)
        event_type = EventType.LATERAL_MOVEMENT
        if target == scenario.target_systems[-1] and scenario.scenario_id == "backup_targeting":
            event_type = EventType.BACKUP_TARGETING
        elif target == scenario.target_systems[-1]:
            event_type = EventType.DATA_ACCESS

        event = create_event(
            event_id=f"SIM-{scenario.scenario_id.upper()}-{step:02d}",
            scenario_id=scenario.scenario_id,
            timestamp=step,
            source=previous_source,
            target=target,
            event_type=event_type,
            vulnerability_id=vuln_id,
            severity="Critical" if target == scenario.target_systems[-1] else "High",
            description=f"Simulated {event_type.value} from {previous_source} to {target}.",
        )
        events.append(event)
        previous_source = target
        step += 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    rows = [event_to_dict(e) for e in events]
    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_PATH, index=False, encoding="utf-8", lineterminator="\n")
    return df


def simulate_all_finbank_scenarios(
    inventory: Optional[pd.DataFrame] = None,
    seed: int = FIXED_SEED,
) -> pd.DataFrame:
    all_frames = []
    for scenario_id in (
        "customer_portal_compromise",
        "employee_compromise",
        "remote_access_compromise",
        "backup_targeting",
    ):
        df = simulate_finbank_attack(scenario_id, inventory=inventory, seed=seed)
        df["scenario_id"] = scenario_id
        all_frames.append(df)
    return pd.concat(all_frames, ignore_index=True)


if __name__ == "__main__":
    result = simulate_finbank_attack("customer_portal_compromise")
    print(result.to_string(index=False))
    print(f"\nSaved to: {OUTPUT_PATH}")

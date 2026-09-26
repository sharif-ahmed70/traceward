# FinBank Incident Simulation

This document describes the FinBank incident simulation module, its purpose, design boundaries, and how it fits into the broader TraceWard pipeline.

## 1. What FinBank Represents

FinBank is a **fictional, controlled demonstration environment** that models a simplified enterprise banking network. It is not based on any real institution, real host inventory, or observed breach data.

The environment includes:

- 8 network nodes: 1 untrusted entry point (`INTERNET`) and 7 host systems (`WEB01`, `APP01`, `AUTH01`, `VPN01`, `EMP01`, `DB01`, `BACKUP01`)
- 9 directed edges representing permitted network traffic corridors
- Deterministic attack scenarios that traverse these corridors in predefined sequences

The FinBank environment exists so that the TraceWard pipeline can be demonstrated end-to-end without relying on external datasets, live scanning, or sensitive operational data.

## 2. Why the Vulnerability Dataset Remains Synthetic

The synthetic vulnerability inventory is used for controlled pipeline validation and demonstration; it should not be interpreted as a real-world vulnerability dataset.

The 1,200-record inventory is generated from the same base vulnerability catalog used by the rest of TraceWard, with system assignments produced by a deterministic weighted-random process (`seed=42`). This ensures:

- The same vulnerabilities can be reused across the supervised, unsupervised, and incident-simulation modules without schema mismatch
- Results are fully reproducible across runs and machines
- No real-world asset exposure, vendor disclosure timelines, or patch-status information is required

Because the dataset is synthetic, TraceWard does not claim that its risk predictions, attack paths, or remediation schedules generalize to uncurated zero-day vulnerabilities or live production environments.

## 3. What the Attack Simulator Does

The attack simulator converts a high-level scenario definition into a chronologically ordered sequence of fictional security events. For each scenario, it:

- Follows the scenario's predefined system path (e.g., `INTERNET → WEB01 → APP01 → DB01`)
- Assigns realistic event types (`initial_access`, `lateral_movement`, `data_access`, etc.)
- Attaches deterministic descriptions and severity labels
- References vulnerabilities from the current inventory
- Produces output in a strict tabular schema required by downstream modules

The simulator is deterministic: repeated executions with the same inventory and seed produce identical event sequences.

## 4. What It Does NOT Do

The FinBank attack simulator:

- Does **not** scan real networks or interact with live hosts
- Does **not** execute exploits, open network connections, or spawn subprocesses
- Does **not** ingest telemetry, IDS alerts, or real incident data
- Does **not** predict whether a specific real-world attack will succeed
- Does **not** replace penetration testing, red-teaming, or incident response

The FinBank environment is fictional and the attacks are simulated. No real systems are attacked or scanned.

## 5. Available Attack Scenarios

TraceWard includes four deterministic FinBank scenarios:

| Scenario ID | Name | Simulated Path |
| :--- | :--- | :--- |
| `customer_portal_compromise` | Customer Portal Compromise | `INTERNET → WEB01 → APP01 → DB01` |
| `employee_compromise` | Employee Compromise | `INTERNET → EMP01 → AUTH01 → APP01 → DB01` |
| `remote_access_compromise` | Remote Access Compromise | `INTERNET → VPN01 → AUTH01 → APP01 → DB01` |
| `backup_targeting` | Backup Targeting | `INTERNET → WEB01 → APP01 → DB01 → BACKUP01` |

Each scenario defines its own entry point, target systems, and event sequence, but all share the same underlying topology and vulnerability inventory.

## 6. How Simulated Events Are Generated

Event generation follows a fixed, scenario-driven process:

1. The scenario specification defines the ordered list of target systems.
2. For each step in the path, the simulator selects an event type from a deterministic mapping tied to the transition (e.g., first hop → `initial_access`, intermediate hops → `lateral_movement`, final hop → `data_access`).
3. A vulnerability is selected from the inventory for the current target system using a fixed random seed.
4. The event record is stamped with a monotonically increasing timestamp, a human-readable description, and a severity label.
5. All events for a scenario are collected into a single DataFrame with the required columns: `event_id`, `scenario_id`, `timestamp`, `source`, `target`, `event_type`, `vulnerability_id`, `severity`, `description`.

Because timestamps, vulnerability selections, and descriptions are derived from fixed seeds and deterministic rules, the event stream is reproducible.

## 7. How TraceWard Processes an Incident

Incident processing begins after events are generated. The correlator:

1. Reads the scenario's event DataFrame and the vulnerability inventory.
2. Identifies affected systems by collecting every unique `target` in the event chain.
3. Collects related vulnerabilities by extracting non-null `vulnerability_id` values.
4. Determines critical assets by checking each affected system's `criticality` score and `internet_exposed` flag against configurable thresholds.
5. Builds an `Incident` object containing:
   - `incident_id`
   - `scenario_id`
   - `entry_point`
   - `affected_systems`
   - `related_vulnerabilities`
   - `event_count`
   - `critical_assets_affected`
   - `attack_sequence`

The incident object is then serialized to a dictionary for downstream consumption by the risk, attack-path, and remediation modules.

## 8. How Attack Paths Are Calculated

Attack path calculation uses the A* search algorithm over a directed, risk-weighted graph of the FinBank topology.

1. The graph is constructed from `data/finbank/network.json` and the system risk summary produced by the risk engine.
2. Each node carries a `normalized_risk` score (0.0–1.0) derived from the predicted vulnerability risks for that system.
3. Edge traversal cost is computed as:
   $$c(u, v) = \max(0.5, \text{round}(2.0 - \text{Risk}(v), 2))$$
   This models the path of least resistance: higher destination risk yields lower traversal impedance.
4. A* search is invoked from the scenario's entry point to its target critical asset.
5. The result includes:
   - `simulated_attack_path`: the ordered list of systems in the cheapest route
   - `risk_weighted_attack_path`: the same route expressed in risk terms
   - `entry_point` and `target_critical_asset`
   - `systems_along_path`: enriched system metadata for each hop
   - `total_risk_cost`: the summed traversal impedance

The attack path is deterministic for a given risk summary and scenario.

## 9. How Remediation Plans Are Generated

Remediation planning uses a Backtracking CSP solver to produce feasible patch schedules that respect operational constraints.

1. The FinBank remediation case builder examines the incident, inventory, and attack path together.
2. It selects one representative high-priority vulnerability per affected system on the attack path.
3. Each selected task is mapped to its authorized team via `SYSTEM_TEAM_MAP`.
4. Tasks are scored by priority, criticality, path position, and exposure to produce a deterministic ordering.
5. The CSP solver assigns tasks to time slots while enforcing:
   - **Team Qualification**: only the mapped team may execute a task
   - **Capacity**: at most 1 task per team per slot
   - **Defensive Dependencies**: perimeter/boundary tasks must precede internal tasks
6. The solver returns a feasible schedule or an explicit infeasible status if constraints conflict.
7. The result includes:
   - `status`: `feasible` or `infeasible`
   - `schedule`: ordered list of tasks with `vuln_id`, `system_id`, `priority`, `team`, `time_slot`, and `depends_on`
   - `metadata`: selection rationale, attack-path alignment, and pending backlog counts

TraceWard does not claim that the generated schedule will produce the exact modeled risk reduction or attack-path change in a real environment.

## 10. How the What-If Simulation Works

The what-if module evaluates the hypothetical defensive impact of hardening a single system.

1. The operator selects a target system and a desired risk reduction factor (10%–90%).
2. The simulator creates an isolated deep copy of the baseline risk summary and graph state; original disk artifacts are never modified.
3. The target system's `normalized_risk` is reduced by the specified factor.
4. A* search is re-run on the modified graph to determine whether the attack path changes.
5. The result reports:
   - `baseline` vs. `simulated` system risk and path cost
   - `deltas`: `risk_reduction`, `path_cost_increase`, `path_diverted`
   - `explanation`: a plain-English summary of the defensive gain

The what-if simulation is a planning exercise only. It does not guarantee that patching a system in the real world will produce the exact modeled percentage reduction or route change.

---

## Important Disclaimers

- The FinBank environment is fictional and the attacks are simulated. No real systems are attacked or scanned.
- The synthetic vulnerability inventory is used for controlled pipeline validation and demonstration; it should not be interpreted as a real-world vulnerability dataset.
- TraceWard's predictions and simulations are intended for educational and decision-support demonstration. They should not be treated as real-world security assessment outputs.

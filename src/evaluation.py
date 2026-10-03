"""Evaluation of the A* and CSP modules (proposal section 28).

A*:  path correctness against exhaustive enumeration, path cost and nodes expanded,
     compared with Uniform Cost Search and Breadth-First Search.
CSP: constraint satisfaction, assignments, backtracks, constraint checks and time for
     plain backtracking vs. MRV/Degree, Forward Checking and AC-3, on three cases:
       - baseline:  the live pipeline case (data/constraints.json)
       - stress:    more tasks per system, a later attack-path deadline and a fourth day
       - overload:  more tasks than the maintenance windows can hold (infeasible)
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from src.astar_search import compare_search_algorithms, enumerate_attack_paths
from src.csp_solver import build_csp_case_from_pipeline, compare_csp_strategies, load_constraint_config
from src.graph_builder import build_graph

OUTPUT_DIR = Path("artifacts/evaluation")


def _case_with(overrides: Dict[str, Any]):
    config = {**load_constraint_config(), **overrides}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(config, f)
        path = f.name
    try:
        case, _ = build_csp_case_from_pipeline(constraints_path=path)
    finally:
        Path(path).unlink(missing_ok=True)
    return case


def csp_evaluation_cases():
    base_slots = load_constraint_config()["time_slots"]
    thursday = ["Thu 10:00", "Thu 15:00", "Thu 20:00", "Thu 23:00"]
    return {
        "baseline": _case_with({}),
        "stress": _case_with({
            "time_slots": base_slots + thursday,
            "tasks_per_attack_path_system": 3,
            "tasks_per_other_system": 2,
            "max_patches_per_day": 5,
            "attack_path_deadline": "Wed 23:00",
        }),
        "overload": _case_with({
            "tasks_per_attack_path_system": 3,
            "tasks_per_other_system": 2,
        }),
    }


def _markdown_table(df: pd.DataFrame) -> str:
    lines = ["| " + " | ".join(df.columns) + " |", "|" + "---|" * len(df.columns)]
    lines += ["| " + " | ".join(str(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join(lines)


def run_evaluation(graph=None, output_dir: Path = OUTPUT_DIR) -> Dict[str, pd.DataFrame]:
    """Run all evaluations and export CSV tables plus a Markdown report."""
    graph = graph if graph is not None else build_graph()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    astar_df = pd.DataFrame(compare_search_algorithms(graph))
    paths_df = pd.DataFrame(enumerate_attack_paths(graph))
    paths_df["path"] = paths_df["path"].map(" -> ".join)

    csp_rows = []
    for case_name, case in csp_evaluation_cases().items():
        for row in compare_csp_strategies(case):
            csp_rows.append({"case": case_name, "tasks": len(case.vulnerabilities), **row})
    csp_df = pd.DataFrame(csp_rows)

    astar_df.to_csv(output_dir / "astar_comparison.csv", index=False)
    paths_df.to_csv(output_dir / "attack_paths.csv", index=False)
    csp_df.to_csv(output_dir / "csp_comparison.csv", index=False)

    report = [
        "# TraceWard Evaluation Report",
        "",
        "## A* vs. uninformed search (INTERNET -> DB01)",
        "",
        _markdown_table(astar_df),
        "",
        "All simple attack paths (exhaustive enumeration, cheapest first):",
        "",
        _markdown_table(paths_df),
        "",
        "## CSP search strategies",
        "",
        _markdown_table(csp_df.drop(columns=["time_ms"])),
        "",
        "Timing (ms) varies by machine and is recorded in csp_comparison.csv.",
        "",
    ]
    (output_dir / "evaluation_report.md").write_text("\n".join(report), encoding="utf-8")
    return {"astar": astar_df, "paths": paths_df, "csp": csp_df}


if __name__ == "__main__":
    results = run_evaluation()
    print(results["astar"].to_string(index=False))
    print()
    print(results["csp"].to_string(index=False))

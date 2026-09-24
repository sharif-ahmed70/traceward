"""TraceWard — main entry point and foundation orchestrator."""

import json
from pathlib import Path
import pandas as pd

from src.preprocessing import preprocess_vulnerabilities
from src.knn_classifier import (
    load_data as load_knn_data,
    get_features_and_target,
    split_data,
    train_and_select_k,
    evaluate_model,
    predict_and_export,
)
from src.risk_engine import build_system_risk_summary
from src.kmeans_clustering import run_kmeans
from src.graph_builder import build_graph
from src.astar_search import run_astar
from src.csp_solver import solve_csp
from src.explainability import (
    explain_risk,
    explain_attack_path,
    explain_patch_priority,
    build_explanation_report,
)

RAW_DATA_PATH = Path("data/raw/vulnerabilities.csv")
PROCESSED_DATA_PATH = Path("data/processed/vulnerabilities_processed.csv")
NETWORK_DATA_PATH = Path("data/network/network.json")


def validate_foundation(
    raw_path=RAW_DATA_PATH,
    processed_path=PROCESSED_DATA_PATH,
    network_path=NETWORK_DATA_PATH,
):
    """
    Validate that shared foundation files exist, match in record count,
    and map cleanly to network nodes.
    Raises FileNotFoundError or ValueError if inconsistent.
    """
    raw_file = Path(raw_path)
    processed_file = Path(processed_path)
    network_file = Path(network_path)

    for file_path in [raw_file, processed_file, network_file]:
        if not file_path.exists():
            raise FileNotFoundError(f"Required foundation file missing: {file_path}")

    raw_df = pd.read_csv(raw_file, keep_default_na=False)
    processed_df = pd.read_csv(processed_file, keep_default_na=False)

    with open(network_file, "r", encoding="utf-8") as f:
        network_data = json.load(f)

    if len(raw_df) != len(processed_df):
        raise ValueError(
            f"Record count mismatch: raw has {len(raw_df)} rows, processed has {len(processed_df)} rows."
        )

    node_ids = {node["id"] for node in network_data.get("nodes", [])}
    raw_systems = set(raw_df["system_id"])
    processed_systems = set(processed_df["system_id"])

    unknown_raw = raw_systems - node_ids
    if unknown_raw:
        raise ValueError(f"Raw data contains unknown system IDs not in network: {unknown_raw}")

    unknown_proc = processed_systems - node_ids
    if unknown_proc:
        raise ValueError(f"Processed data contains unknown system IDs not in network: {unknown_proc}")

    return True


def get_foundation_status(
    raw_path=RAW_DATA_PATH,
    processed_path=PROCESSED_DATA_PATH,
    network_path=NETWORK_DATA_PATH,
):
    """Validate foundation and return a dictionary of key status metrics."""
    validate_foundation(raw_path, processed_path, network_path)

    raw_df = pd.read_csv(raw_path, keep_default_na=False)
    processed_df = pd.read_csv(processed_path, keep_default_na=False)

    with open(network_path, "r", encoding="utf-8") as f:
        network_data = json.load(f)

    return {
        "raw_records": len(raw_df),
        "processed_records": len(processed_df),
        "network_nodes": len(network_data.get("nodes", [])),
        "network_edges": len(network_data.get("edges", [])),
    }


def run_pipeline():
    """Execute the full end-to-end TraceWard pipeline demonstration."""
    print("=" * 70)
    print("TraceWard — Integrated Pipeline Execution")
    print("Cyber Risk Analysis, Attack Path Detection & Smart Remediation Planning")
    print("=" * 70)
    print()

    # Step 1: Foundation validation
    print("[1/8] Validating foundation datasets & network...")
    status = get_foundation_status()
    print("      Foundation Status: READY")
    print(f"      Raw vulnerabilities: {status['raw_records']}")
    print(f"      Processed vulnerabilities: {status['processed_records']}")
    print(f"      Network nodes: {status['network_nodes']}")
    print(f"      Network edges: {status['network_edges']}")
    print()

    # Step 2: Preprocessing check
    print("[2/8] Preprocessing verification...")
    if not PROCESSED_DATA_PATH.exists():
        print("      Generating processed vulnerabilities dataset...")
        preprocess_vulnerabilities(RAW_DATA_PATH, PROCESSED_DATA_PATH)
    print(f"      Input features: 7 security dimensions ready for ML.")
    print()

    # Step 3: KNN Risk Prediction
    print("[3/8] Training KNN Risk Classifier & Generating Predictions...")
    knn_df = load_knn_data(str(PROCESSED_DATA_PATH))
    X, y, ids = get_features_and_target(knn_df)
    X_tr, X_te, y_tr, y_te, id_tr, id_te = split_data(X, y, ids, test_size=0.2, random_state=42)
    knn_model, best_k = train_and_select_k(X_tr, y_tr, X_te, y_te)
    metrics = evaluate_model(knn_model, X_te, y_te)
    predictions = predict_and_export(knn_model, X_te, y_te, id_te)
    print(f"      KNN Model: Best K={best_k}, Accuracy={metrics['accuracy']:.4f}, F1={metrics['f1']:.4f}")
    print(f"      Saved: artifacts/knn/predictions.csv ({len(predictions)} test predictions)")
    print()

    # Step 4: Risk Engine Aggregation
    print("[4/8] Aggregating System Risk Scores...")
    risk_summary = build_system_risk_summary(
        input_path="artifacts/knn/predictions.csv",
        output_path="artifacts/risk/system_risk_summary.csv",
    )
    print(f"      Summarized {len(risk_summary)} systems by risk severity:")
    for _, row in risk_summary.head(4).iterrows():
        print(f"        - {row['system_id']}: Normalized Risk={row['normalized_risk']:.3f}, Highest={row['highest_risk']}")
    print()

    # Step 5: K-Means Clustering
    print("[5/8] Running K-Means Structural Clustering...")
    cluster_df = run_kmeans()
    print(f"      Vulnerabilities grouped into {cluster_df['cluster_id'].nunique()} structural profiles.")
    print("      Saved: artifacts/kmeans/cluster_assignments.csv")
    print()

    # Step 6: Attack Graph Generation
    print("[6/8] Generating Risk-Weighted Attack Graph...")
    graph = build_graph()
    print(f"      Constructed topology with {len(graph['nodes'])} systems and {len(graph['edges'])} directed edges.")
    print()

    # Step 7: A* Attack Path Detection
    print("[7/8] Running A* Search for Critical Attack Path...")
    attack_path = run_astar(graph, start="INTERNET", goal="DB01")
    path_str = " -> ".join(attack_path["path"])
    print(f"      Critical Path Identified: {path_str}")
    print(f"      Accumulated Path Cost: {attack_path['total_cost']}")
    print("      Saved: artifacts/astar/attack_path.json")
    print()

    # Step 8: CSP Remediation Scheduling & Explainability
    print("[8/8] Solving Constraint Satisfaction Problem (CSP) for Remediation...")
    csp_result = solve_csp()
    print(f"      Remediation Solver: {csp_result['solver']} (Status: {csp_result['status']})")
    meta = csp_result.get("metadata", {})
    if meta.get("source") == "live_pipeline":
        print(f"      Pipeline Integration: Selected {meta['selected_task_count']} high-impact tasks from {meta['total_evaluated_vulnerabilities']} predictions")
        print(f"      Attack Path Alignment: Prioritized perimeter and intermediate targets on {', '.join(meta['attack_path_systems'])}")
        print(f"      Pending Backlog: {meta['pending_backlog_count']} vulnerabilities queued for subsequent scheduling cycles")
    print("      Generated Feasible Patch Schedule:")
    for task in csp_result["schedule"]:
        dep_str = f" [Prerequisite: {', '.join(task['depends_on'])}]" if task.get("depends_on") else ""
        print(f"        - {task['time_slot']}: {task['team']} -> {task['vuln_id']} ({task['priority']} on {task['system_id']}){dep_str}")

    csp_out = Path("artifacts/csp/patch_schedule.json")
    csp_out.parent.mkdir(parents=True, exist_ok=True)
    with open(csp_out, "w", encoding="utf-8") as f:
        json.dump(csp_result["schedule"], f, indent=2)
    print("      Saved: artifacts/csp/patch_schedule.json")
    print()

    # Explainability demo
    top_vuln = predictions.iloc[0]
    explanation = explain_risk(
        top_vuln["vuln_id"],
        top_vuln["system_id"],
        top_vuln["predicted_risk"],
        risk_factors=[f"Predicted class: {top_vuln['predicted_risk']}", f"System: {top_vuln['system_id']}"],
    )
    print("Explainability Sample:")
    print(f"  {explanation['summary']}")
    print()
    print("=" * 70)
    print("Pipeline Execution Complete. System Ready for Faculty Demonstration!")
    print("To launch the interactive dashboard, run: streamlit run dashboard/app.py")
    print("=" * 70)


def main():
    """Main entry point for TraceWard."""
    run_pipeline()


if __name__ == "__main__":
    main()

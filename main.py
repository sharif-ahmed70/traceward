"""TraceWard — main entry point and foundation orchestrator."""

import json
from pathlib import Path
import pandas as pd

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


def main():
    """Main entry point for TraceWard."""
    print("TraceWard")
    print("Cyber Risk Analysis, Attack Path Detection & Smart Remediation Planning")
    print()

    status = get_foundation_status()

    print("Foundation Status: READY")
    print(f"Raw vulnerabilities: {status['raw_records']}")
    print(f"Processed vulnerabilities: {status['processed_records']}")
    print(f"Network nodes: {status['network_nodes']}")
    print(f"Network edges: {status['network_edges']}")


if __name__ == "__main__":
    main()

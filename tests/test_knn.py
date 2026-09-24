import os
import pandas as pd
from src.knn_classifier import run_knn_classification

def test_knn_execution():
    # Run classifier to generate predictions artifact
    run_knn_classification()
    
    # Verify artifact generation
    output_path = "artifacts/knn/predictions.csv"
    assert os.path.exists(output_path), "Predictions CSV artifact not generated."
    
    df_pred = pd.read_csv(output_path)
    expected_cols = ['vuln_id', 'system_id', 'actual_risk', 'predicted_risk']
    for col in expected_cols:
        assert col in df_pred.columns, f"Missing required column: {col}"
    assert len(df_pred) > 0, "Predictions file is empty."
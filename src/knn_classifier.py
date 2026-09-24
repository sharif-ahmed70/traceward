import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, confusion_matrix

def run_knn_classification():
    file_path = "data/processed/vulnerabilities_processed.csv"
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Processed dataset not found at {file_path}")
        
    df = pd.read_csv(file_path)
    
    # Mandatory columns check
    mandatory_cols = ['vuln_id', 'system_id', 'risk_label']
    for col in mandatory_cols:
        if col not in df.columns:
            raise ValueError(f"Missing mandatory column: {col}")
            
    feature_columns = [
        'attack_complexity', 
        'privileges_required', 
        'user_interaction', 
        'confidentiality_impact', 
        'integrity_impact', 
        'availability_impact', 
        'exploit_probability'
    ]
    
    X = df[feature_columns]
    y = df['risk_label']
    
    # Train-Test Split (Keeping scaler fitting inside training boundaries to avoid leakage)
    X_train, X_test, y_train, y_test, id_train, id_test = train_test_split(
        X, y, df[['vuln_id', 'system_id']], test_size=0.2, random_state=42
    )
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # KNN Model training (k=5)
    k_value = 5
    knn = KNeighborsClassifier(n_neighbors=k_value)
    knn.fit(X_train_scaled, y_train)
    
    y_pred = knn.predict(X_test_scaled)
    
    # Evaluation metrics report
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Preparing prediction dataframe for downstream modules
    test_indices = X_test.index
    output_df = pd.DataFrame({
        'vuln_id': df.loc[test_indices, 'vuln_id'].values,
        'system_id': df.loc[test_indices, 'system_id'].values,
        'actual_risk': y_test.values,
        'predicted_risk': y_pred
    })
    
    # Saving artifacts to required path
    output_dir = "artifacts/knn"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "predictions.csv")
    output_df.to_csv(output_path, index=False)
    
    print(f"Successfully saved KNN predictions to {output_path}")

if __name__ == "__main__":
    run_knn_classification()
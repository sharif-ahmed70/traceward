"""KNN classifier to predict the risk level of new vulnerabilities.

Input contract:
- Expects a CSV with columns: vuln_id, system_id, attack_complexity,
  privileges_required, user_interaction, confidentiality_impact,
  integrity_impact, availability_impact, exploit_probability, risk_label.
- get_features_and_target() returns X (7 feature columns), y (risk_label), and
  ids (vuln_id + system_id) aligned by index. Do not include risk_label,
  vuln_id, system_id, or description in X.
"""

import pandas as pd
from pathlib import Path
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


def load_data(path="data/processed/vulnerabilities_processed.csv"):
    """Load vulnerability data from a CSV file into a DataFrame."""
    df = pd.read_csv(path)
    return df


def get_features_and_target(df):
    """Split DataFrame into features, target, and aligned ids.

    Returns:
        X: DataFrame with the 7 security feature columns only:
           attack_complexity, privileges_required, user_interaction,
           confidentiality_impact, integrity_impact, availability_impact,
           exploit_probability.
        y: Series of risk_label.
        ids: DataFrame with vuln_id and system_id, aligned by index.
    """
    feature_cols = [
        "attack_complexity",
        "privileges_required",
        "user_interaction",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
        "exploit_probability",
    ]
    X = df[feature_cols]
    y = df["risk_label"]
    ids = df[["vuln_id", "system_id"]]
    return X, y, ids


def split_data(X, y, ids, test_size=0.2, random_state=42):
    """Stratified train/test split with aligned ids and feature scaling.

    Categorical columns are one-hot encoded, and numeric columns are scaled
    with StandardScaler fit ONLY on X_train. No fitting on full data or test data.

    Returns:
        X_train_scaled, X_test_scaled, y_train, y_test, ids_train, ids_test
    """
    X_train, X_test, y_train, y_test, ids_train, ids_test = train_test_split(
        X, y, ids, test_size=test_size, random_state=random_state, stratify=y
    )

    numeric_cols = X_train.select_dtypes(include=["number"]).columns.tolist()
    categorical_cols = X_train.select_dtypes(exclude=["number"]).columns.tolist()

    transformers = []
    if numeric_cols:
        transformers.append(("num", StandardScaler(), numeric_cols))
    if categorical_cols:
        transformers.append(("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols))

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")

    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)

    if hasattr(X_train_scaled, "toarray"):
        X_train_scaled = X_train_scaled.toarray()
        X_test_scaled = X_test_scaled.toarray()

    feature_names = list(preprocessor.get_feature_names_out())
    X_train_scaled = pd.DataFrame(X_train_scaled, columns=feature_names, index=X_train.index)
    X_test_scaled = pd.DataFrame(X_test_scaled, columns=feature_names, index=X_test.index)

    return X_train_scaled, X_test_scaled, y_train, y_test, ids_train, ids_test


def train_and_select_k(X_train, y_train, X_test, y_test):
    """Train KNN for multiple K values and select the best by test accuracy.

    Evaluation is done on the held-out test set (not cross-validation).
    Prints a comparison table and returns the best fitted model and chosen K.

    Returns:
        best_model: Fitted KNeighborsClassifier.
        best_k: Integer K value with highest test accuracy.
    """
    k_values = [3, 5, 7, 9]
    results = []

    for k in k_values:
        model = KNeighborsClassifier(n_neighbors=k)
        model.fit(X_train, y_train)
        acc = model.score(X_test, y_test)
        results.append((k, acc))

    print(f"{'K':<6} {'Test Accuracy':>14}")
    print("-" * 22)
    for k, acc in results:
        print(f"{k:<6} {acc:>14.4f}")

    best_k, best_acc = max(results, key=lambda x: x[1])
    best_model = KNeighborsClassifier(n_neighbors=best_k)
    best_model.fit(X_train, y_train)

    print(f"\nSelected K={best_k} with test accuracy={best_acc:.4f}")
    return best_model, best_k


def evaluate_model(model, X_test, y_test):
    """Evaluate model performance and write a report to artifacts/knn/evaluation_report.txt.

    Computes Accuracy, Precision, Recall, and F1-Score (weighted), plus a
    confusion matrix with labels ordered Low, Medium, High, Critical.

    Returns:
        dict with accuracy, precision, recall, f1, and confusion_matrix.
    """
    LABELS = ["Low", "Medium", "High", "Critical"]
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=LABELS)

    best_k = getattr(model, "n_neighbors", "N/A")

    report_lines = [
        "KNN Evaluation Report",
        "=" * 40,
        f"Selected K: {best_k}",
        "-" * 40,
        f"Accuracy:  {acc:.4f}",
        f"Precision: {prec:.4f}",
        f"Recall:    {rec:.4f}",
        f"F1-Score:  {f1:.4f}",
        "",
        "Confusion Matrix (rows=true, cols=pred):",
        f"Labels: {LABELS}",
    ]
    for i, row in enumerate(cm):
        report_lines.append(f"  {LABELS[i]}: {row.tolist()}")

    report = "\n".join(report_lines)
    print(report)

    output_path = Path("artifacts/knn/evaluation_report.txt")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    print(f"\nReport written to {output_path}")

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": cm,
    }


def predict_and_export(model, X_test, y_test, ids_test):
    """Build prediction DataFrame and save to artifacts/knn/predictions.csv.

    Returns:
        predictions: DataFrame with vuln_id, system_id, actual_risk, predicted_risk.
    """
    y_pred = model.predict(X_test)

    predictions = pd.DataFrame({
        "vuln_id": ids_test["vuln_id"].values,
        "system_id": ids_test["system_id"].values,
        "actual_risk": y_test.values,
        "predicted_risk": y_pred,
    })

    output_path = Path("artifacts/knn/predictions.csv")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(output_path, index=False)
    print(f"Predictions exported to {output_path} ({len(predictions)} rows)")
    return predictions


if __name__ == "__main__":
    print("[1/5] Loading data...")
    df = load_data()

    print("[2/5] Extracting features and target...")
    X, y, ids = get_features_and_target(df)

    print("[3/5] Splitting and scaling data...")
    X_train, X_test, y_train, y_test, ids_train, ids_test = split_data(X, y, ids)

    print("[4/5] Training KNN and selecting best K...")
    best_model, best_k = train_and_select_k(X_train, y_train, X_test, y_test)

    print("[5/5] Evaluating model and exporting predictions...")
    metrics = evaluate_model(best_model, X_test, y_test)
    predictions = predict_and_export(best_model, X_test, y_test, ids_test)

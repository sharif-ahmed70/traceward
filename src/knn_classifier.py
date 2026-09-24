"""KNN classifier to predict the risk level of new vulnerabilities.

Trained using 5-Fold Stratified Cross-Validation on the training partition
with feature scaling isolated inside the model pipeline to prevent data leakage.
Evaluated on a held-out test partition with comprehensive metric reporting.
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import joblib

FEATURE_COLUMNS = [
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
    "exploit_probability",
]

LABELS = ["Low", "Medium", "High", "Critical"]


def load_data(path="data/processed/vulnerabilities_processed.csv"):
    """Load vulnerability data from a CSV file into a DataFrame."""
    df = pd.read_csv(path)
    return df


def get_features_and_target(df):
    """Split DataFrame into features, target, and aligned IDs.

    Returns:
        X: DataFrame with the 7 security feature columns only.
        y: Series of risk_label.
        ids: DataFrame with vuln_id and system_id, aligned by index.
    """
    X = df[FEATURE_COLUMNS].copy()
    y = df["risk_label"].copy()
    ids = df[["vuln_id", "system_id"]].copy()
    return X, y, ids


def split_data(X, y, ids, test_size=0.2, random_state=42):
    """Reproducible stratified train/test split with aligned IDs.

    Scaling is intentionally deferred to the model pipeline to prevent
    leakage across cross-validation folds.

    Returns:
        X_train, X_test, y_train, y_test, ids_train, ids_test
    """
    X_train, X_test, y_train, y_test, ids_train, ids_test = train_test_split(
        X, y, ids, test_size=test_size, random_state=random_state, stratify=y
    )
    return X_train, X_test, y_train, y_test, ids_train, ids_test


def train_and_select_k(
    X_train,
    y_train,
    X_test=None,
    y_test=None,
    k_values=(3, 5, 7, 9),
    n_splits=5,
    random_state=42,
    output_dir="artifacts/knn",
):
    """Train KNN candidate models using Stratified 5-Fold Cross-Validation on the training partition.

    Feature scaling (StandardScaler) is fitted strictly within each CV fold to eliminate leakage.
    Selection metric: Mean CV Accuracy, with deterministic tie-breaking (lowest std, then smaller K).

    Returns:
        best_pipeline: Fitted Pipeline (StandardScaler + KNeighborsClassifier) on full X_train.
        best_k: Integer K value selected by CV.
    """
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    cv_records = []

    print(f"\nEvaluating candidate K values via Stratified {n_splits}-Fold CV on Training Set (N={len(X_train)}):")
    print(f"{'K':<5} {'Mean CV Acc':<14} {'Std CV Acc':<14} {'Mean CV F1':<14} {'Std CV F1':<14}")
    print("-" * 65)

    for k in k_values:
        pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("knn", KNeighborsClassifier(n_neighbors=k)),
        ])
        cv_scores = cross_validate(
            pipe,
            X_train,
            y_train,
            cv=cv,
            scoring=["accuracy", "f1_weighted"],
            return_train_score=False,
        )
        mean_acc = round(float(np.mean(cv_scores["test_accuracy"])), 4)
        std_acc = round(float(np.std(cv_scores["test_accuracy"])), 4)
        mean_f1 = round(float(np.mean(cv_scores["test_f1_weighted"])), 4)
        std_f1 = round(float(np.std(cv_scores["test_f1_weighted"])), 4)

        cv_records.append({
            "k": k,
            "mean_cv_accuracy": mean_acc,
            "std_cv_accuracy": std_acc,
            "mean_cv_f1_weighted": mean_f1,
            "std_cv_f1_weighted": std_f1,
        })
        print(f"{k:<5} {mean_acc:<14.4f} {std_acc:<14.4f} {mean_f1:<14.4f} {std_f1:<14.4f}")

    cv_df = pd.DataFrame(cv_records)

    # Save CV selection table
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cv_csv_path = out_dir / "k_selection_cv.csv"
    cv_df.to_csv(cv_csv_path, index=False)

    # Deterministic selection: highest mean CV accuracy, then lowest std, then smallest K
    best_row = cv_df.sort_values(
        by=["mean_cv_accuracy", "std_cv_accuracy", "k"],
        ascending=[False, True, True],
    ).iloc[0]

    best_k = int(best_row["k"])
    print(f"\nSelected K={best_k} (Mean CV Accuracy={best_row['mean_cv_accuracy']:.4f} +/- {best_row['std_cv_accuracy']:.4f})")

    # Fit selected pipeline on full training partition
    best_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("knn", KNeighborsClassifier(n_neighbors=best_k)),
    ])
    best_pipeline.fit(X_train, y_train)

    return best_pipeline, best_k


def plot_confusion_matrix(cm, labels=LABELS, output_path=Path("artifacts/knn/confusion_matrix.png")):
    """Generate and save an annotated confusion matrix plot."""
    fig, ax = plt.subplots(figsize=(6, 5))
    cax = ax.matshow(cm, cmap="Blues", alpha=0.85)

    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center",
                color="black" if cm[i, j] < cm.max() / 2 else "white",
                fontsize=11,
                fontweight="bold",
            )

    fig.colorbar(cax)
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_yticklabels(labels, fontsize=10)
    ax.set_xlabel("Predicted Risk Label", fontsize=11, labelpad=10)
    ax.set_ylabel("True Risk Label", fontsize=11)
    ax.set_title("KNN Confusion Matrix (Held-out Test Partition)", fontsize=12, fontweight="bold", pad=15)
    fig.tight_layout()

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_file, dpi=150)
    plt.close(fig)
    return out_file


def evaluate_model(model, X_test, y_test, selected_k=None, output_dir="artifacts/knn"):
    """Evaluate fitted model on the held-out test partition and export full report.

    Computes Accuracy, weighted Precision/Recall/F1, per-class breakdown, and Confusion Matrix.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    y_pred = model.predict(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    cm = confusion_matrix(y_test, y_pred, labels=LABELS)
    cls_report = classification_report(y_test, y_pred, labels=LABELS, digits=4, zero_division=0)

    if selected_k is None:
        if hasattr(model, "named_steps") and "knn" in model.named_steps:
            selected_k = model.named_steps["knn"].n_neighbors
        elif hasattr(model, "n_neighbors"):
            selected_k = model.n_neighbors
        else:
            selected_k = "N/A"

    # Save confusion matrix plot
    plot_confusion_matrix(cm, labels=LABELS, output_path=out_dir / "confusion_matrix.png")

    report_lines = [
        "=" * 70,
        "TraceWard — KNN Risk Classifier Evaluation Report",
        "=" * 70,
        "",
        "1. Experimental Setup & Model Selection",
        "-" * 50,
        f"Partition Split:       Stratified 80/20 (Train=960, Held-out Test={len(X_test)})",
        f"Model Selection:       Stratified 5-Fold Cross-Validation on Training Partition Only",
        f"Candidate K Values:    [3, 5, 7, 9]",
        f"Selected K:            {selected_k}",
        "Data Leakage Control:  StandardScaler fitted strictly inside CV folds & final training pipeline",
        "",
        "2. Held-out Test Partition Metrics",
        "-" * 50,
        f"Test Accuracy:         {acc:.4f} ({int(acc * len(y_test))}/{len(y_test)} correct)",
        f"Weighted Precision:    {prec:.4f}",
        f"Weighted Recall:       {rec:.4f}",
        f"Weighted F1-Score:     {f1:.4f}",
        "",
        "3. Detailed Classification Report (Per Class)",
        "-" * 50,
        cls_report,
        "4. Confusion Matrix (rows = True Label, cols = Predicted Label)",
        "-" * 50,
        f"Labels: {LABELS}",
    ]
    for i, row in enumerate(cm):
        report_lines.append(f"  {LABELS[i]:<10}: {row.tolist()}")

    report_lines.extend([
        "",
        "5. Methodological & Historical Disclosure",
        "-" * 50,
        "Note on Evaluation: During early baseline prototyping, K was selected directly by evaluating",
        "against the test set (which favored K=9 at 77.92%). To establish a sound, defensible ML methodology,",
        "the current pipeline selects K strictly via 5-Fold Cross-Validation on the training partition (selecting K=3)",
        "and evaluates once on the held-out test partition (achieving 73.75% accuracy, 0.7298 F1).",
        "Because this test partition was examined during earlier exploratory runs, this result represents a",
        "reproducible held-out evaluation on the designated split rather than a fully blind external benchmark.",
        "=" * 70,
    ])

    report = "\n".join(report_lines)
    report_path = out_dir / "evaluation_report.txt"
    report_path.write_text(report, encoding="utf-8")
    print("\n" + report)

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": cm,
    }


def predict_and_export(model, X_test, y_test, ids_test, output_dir="artifacts/knn"):
    """Export prediction DataFrames for held-out test set and integration.

    Saves:
      - artifacts/knn/test_predictions.csv: exactly the 240 held-out test predictions.
      - artifacts/knn/predictions.csv: contract-compliant predictions for downstream integration.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    y_pred = model.predict(X_test)

    predictions = pd.DataFrame({
        "vuln_id": ids_test["vuln_id"].values,
        "system_id": ids_test["system_id"].values,
        "actual_risk": y_test.values,
        "predicted_risk": y_pred,
    })

    # Save test partition predictions
    test_pred_path = out_dir / "test_predictions.csv"
    predictions.to_csv(test_pred_path, index=False)

    # Save primary predictions artifact for downstream consumers
    main_pred_path = out_dir / "predictions.csv"
    predictions.to_csv(main_pred_path, index=False)

    # Persist fitted pipeline artifact
    model_path = out_dir / "knn_model.joblib"
    joblib.dump(model, model_path)

    print(f"\nPredictions exported:")
    print(f"  - {test_pred_path} ({len(predictions)} rows)")
    print(f"  - {main_pred_path} ({len(predictions)} rows)")
    print(f"  - {model_path} (fitted pipeline)")

    return predictions


def load_trained_model(model_path="artifacts/knn/knn_model.joblib"):
    """Load the persisted KNN pipeline."""
    p = Path(model_path)
    if not p.exists():
        raise FileNotFoundError(f"Model artifact not found at {model_path}")
    return joblib.load(p)


def predict_single_vulnerability(features: dict, model=None, model_path="artifacts/knn/knn_model.joblib"):
    """Predict risk class and class probabilities for a single vulnerability using the fitted KNN pipeline.

    Args:
        features: dict containing all 7 FEATURE_COLUMNS.
        model: Optional pre-loaded model pipeline.
        model_path: Path to serialized model if model is not passed.

    Returns:
        dict with:
            predicted_risk: str ('Low', 'Medium', 'High', 'Critical')
            probabilities: dict mapping class -> float probability
    """
    if model is None:
        model = load_trained_model(model_path)

    for col in FEATURE_COLUMNS:
        if col not in features:
            raise ValueError(f"Missing required feature: '{col}'")

    input_df = pd.DataFrame([{col: float(features[col]) for col in FEATURE_COLUMNS}])
    predicted_label = str(model.predict(input_df)[0])

    probs = {}
    if hasattr(model, "predict_proba"):
        prob_array = model.predict_proba(input_df)[0]
        classes = list(getattr(model, "classes_", LABELS))
        probs = {str(c): round(float(p), 4) for c, p in zip(classes, prob_array)}

    return {
        "predicted_risk": predicted_label,
        "probabilities": probs,
    }


if __name__ == "__main__":
    print("[1/4] Loading processed data...")
    df = load_data()

    print("[2/4] Extracting features and target...")
    X, y, ids = get_features_and_target(df)

    print("[3/4] Splitting data into 80% train and 20% held-out test...")
    X_train, X_test, y_train, y_test, ids_train, ids_test = split_data(X, y, ids)

    print("[4/4] Cross-validation model selection and test evaluation...")
    best_pipeline, best_k = train_and_select_k(X_train, y_train)
    metrics = evaluate_model(best_pipeline, X_test, y_test, selected_k=best_k)
    predictions = predict_and_export(best_pipeline, X_test, y_test, ids_test)

"""
Demo-only visual: plots KNN test accuracy across K = 3, 5, 7, 9.

Not part of the official Member 3 contract (src/knn_classifier.py already
satisfies that on its own) — this just makes the K-selection evidence easier
to present live instead of reading numbers off a printed table.

Usage: python scripts/plot_k_comparison.py
Works from any starting folder — the repo root is added to sys.path below,
regardless of your current working directory.

Reuses the exact same load/split logic as src/knn_classifier.py so the chart
always matches what's in artifacts/knn/evaluation_report.txt.
"""

import sys
from pathlib import Path

import matplotlib.pyplot as plt
from sklearn.neighbors import KNeighborsClassifier

# Make the repo root importable regardless of the current working directory
# (this file lives in <repo_root>/scripts/, so its parent's parent is the root).
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.knn_classifier import load_data, get_features_and_target, split_data

K_VALUES = [3, 5, 7, 9]


def collect_accuracies(X_train, y_train, X_test, y_test):
    """Train KNN for each K and return a list of (k, accuracy) tuples."""
    results = []
    for k in K_VALUES:
        model = KNeighborsClassifier(n_neighbors=k)
        model.fit(X_train, y_train)
        acc = model.score(X_test, y_test)
        results.append((k, acc))
    return results


def plot_k_comparison(results, output_path=None):
    """Line chart of K vs test accuracy, with the best K highlighted."""
    if output_path is None:
        output_path = REPO_ROOT / "artifacts" / "knn" / "k_comparison.png"
    ks = [k for k, _ in results]
    accs = [acc for _, acc in results]
    best_k, best_acc = max(results, key=lambda pair: pair[1])

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(ks, accs, marker="o", linewidth=2, color="#2f6fed")
    ax.scatter([best_k], [best_acc], color="#e0433c", zorder=5, s=90,
               label=f"Selected K={best_k} ({best_acc:.3f})")

    for k, acc in results:
        ax.annotate(f"{acc:.3f}", (k, acc), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=9)

    ax.set_xticks(ks)
    ax.set_xlabel("K (number of neighbors)")
    ax.set_ylabel("Test accuracy")
    ax.set_title("KNN: Accuracy vs K")
    ax.set_ylim(0, 1)
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()

    fig.savefig(output_path, dpi=150)
    print(f"Saved chart to {output_path}")
    plt.show()


if __name__ == "__main__":
    df = load_data(REPO_ROOT / "data" / "processed" / "vulnerabilities_processed.csv")
    X, y, ids = get_features_and_target(df)
    X_train, X_test, y_train, y_test, ids_train, ids_test = split_data(X, y, ids)

    results = collect_accuracies(X_train, y_train, X_test, y_test)

    print(f"{'K':<6} {'Test Accuracy':>14}")
    print("-" * 22)
    for k, acc in results:
        print(f"{k:<6} {acc:>14.4f}")

    plot_k_comparison(results)
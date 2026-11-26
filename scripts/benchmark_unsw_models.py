"""Benchmark IsolationForest baseline vs supervised RandomForest on UNSW-NB15."""

import argparse
from pathlib import Path
import sys
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ml.feature_schema import FLOW_FEATURES  # noqa: E402
from scripts.train_model import build_pipeline, build_preprocessor  # noqa: E402
from scripts.train_unsw_model import (  # noqa: E402
    DEFAULT_TEST_CSV,
    DEFAULT_TRAIN_CSV,
    DEFAULT_UNSW_MODEL_PATH,
    load_unsw_testing_data,
)

DEFAULT_BEST_MODEL_PATH = PROJECT_ROOT / "models" / "unsw_best_model.joblib"


def build_random_forest_pipeline(n_estimators=200, random_state=42, n_jobs=-1):
    """Build preprocessing + balanced_subsample RandomForestClassifier pipeline."""
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=n_jobs,
    )
    return Pipeline(
        steps=[
            ("preprocessor", build_preprocessor()),
            ("model", clf),
        ]
    )


def compute_binary_metrics(y_true, y_pred, continuous_scores):
    """Compute precision, recall, F1, confusion matrix, ROC-AUC, and PR-AUC."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))

    has_both_classes = len(np.unique(y_true)) >= 2
    roc_auc = float(roc_auc_score(y_true, continuous_scores)) if has_both_classes else 0.0
    pr_auc = float(average_precision_score(y_true, continuous_scores)) if has_both_classes else 0.0

    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": cm.tolist(),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def tune_threshold_on_validation(y_val, val_probs):
    """Select the probability threshold maximizing F1-score on validation data only."""
    best_threshold = 0.5
    best_f1 = -1.0

    for threshold in np.round(np.linspace(0.10, 0.90, 81), 2):
        preds = (val_probs >= threshold).astype(int)
        score = float(f1_score(y_val, preds, zero_division=0))
        if score > best_f1:
            best_f1 = score
            best_threshold = float(threshold)

    return best_threshold, best_f1


def _load_or_fit_baseline_isolation_forest(baseline_model_path, X_train_benign, random_state):
    """Load preserved UNSW IsolationForest baseline without modifying it, or fit in memory."""
    if baseline_model_path is not None and Path(baseline_model_path).exists():
        loaded = joblib.load(baseline_model_path)
        pipeline = loaded["pipeline"] if isinstance(loaded, dict) and "pipeline" in loaded else loaded
        score_scale = float(loaded.get("score_scale", 0.1)) if isinstance(loaded, dict) else 0.1
        return pipeline, score_scale, True

    pipeline = build_pipeline(contamination=0.05, n_estimators=200, random_state=random_state)
    pipeline.fit(X_train_benign[FLOW_FEATURES])
    train_scores = pipeline.decision_function(X_train_benign[FLOW_FEATURES])
    score_scale = float(max(np.std(train_scores), 0.05))
    return pipeline, score_scale, False


def _evaluate_isolation_forest(pipeline, X_eval, y_eval):
    """Score and evaluate an IsolationForest pipeline (higher anomaly score = attack)."""
    raw_preds = pipeline.predict(X_eval[FLOW_FEATURES])
    y_pred = np.where(raw_preds == -1, 1, 0)
    anomaly_scores = -pipeline.decision_function(X_eval[FLOW_FEATURES])
    return compute_binary_metrics(y_eval, y_pred, anomaly_scores)


def _evaluate_random_forest(pipeline, X_eval, y_eval, threshold):
    """Score and evaluate a RandomForestClassifier pipeline at a fixed threshold."""
    probs = pipeline.predict_proba(X_eval[FLOW_FEATURES])[:, 1]
    y_pred = (probs >= threshold).astype(int)
    return compute_binary_metrics(y_eval, y_pred, probs)


def benchmark_and_save_best(
    train_csv=DEFAULT_TRAIN_CSV,
    test_csv=DEFAULT_TEST_CSV,
    baseline_model_path=DEFAULT_UNSW_MODEL_PATH,
    best_model_path=DEFAULT_BEST_MODEL_PATH,
    chunksize=25000,
    n_estimators=200,
    val_size=0.2,
    random_state=42,
):
    """Compare IsolationForest vs RandomForest using a leak-free validation split."""
    X_train_all, y_train_all, _ = load_unsw_testing_data(train_csv, chunksize=chunksize)
    X_test, y_test, _ = load_unsw_testing_data(test_csv, chunksize=chunksize)

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train_all[FLOW_FEATURES],
        y_train_all,
        test_size=val_size,
        stratify=y_train_all,
        random_state=random_state,
    )

    benign_tr = X_tr.loc[y_tr == 0]
    if benign_tr.empty:
        raise ValueError("Training split must contain benign rows (label == 0).")

    iso_pipeline, iso_score_scale, loaded_preserved_baseline = _load_or_fit_baseline_isolation_forest(
        baseline_model_path,
        benign_tr,
        random_state=random_state,
    )

    rf_pipeline = build_random_forest_pipeline(
        n_estimators=n_estimators,
        random_state=random_state,
    )
    rf_pipeline.fit(X_tr[FLOW_FEATURES], y_tr)

    # Tune threshold and select best model strictly on validation split (never touch X_test).
    val_rf_probs = rf_pipeline.predict_proba(X_val[FLOW_FEATURES])[:, 1]
    tuned_threshold, _ = tune_threshold_on_validation(y_val, val_rf_probs)

    val_iso_metrics = _evaluate_isolation_forest(iso_pipeline, X_val, y_val)
    val_rf_metrics = _evaluate_random_forest(rf_pipeline, X_val, y_val, tuned_threshold)

    rf_wins = (val_rf_metrics["f1_score"], val_rf_metrics["pr_auc"]) >= (
        val_iso_metrics["f1_score"],
        val_iso_metrics["pr_auc"],
    )

    # Single final evaluation on the held-out UNSW-NB15 testing set.
    test_iso_metrics = _evaluate_isolation_forest(iso_pipeline, X_test, y_test)
    test_rf_metrics = _evaluate_random_forest(rf_pipeline, X_test, y_test, tuned_threshold)

    if rf_wins:
        selected_type = "random_forest"
        selected_pipeline = rf_pipeline
        selected_threshold = tuned_threshold
        selected_val_metrics = val_rf_metrics
        selected_test_metrics = test_rf_metrics
        selected_score_scale = 0.25
    else:
        selected_type = "isolation_forest"
        selected_pipeline = iso_pipeline
        selected_threshold = 0.0
        selected_val_metrics = val_iso_metrics
        selected_test_metrics = test_iso_metrics
        selected_score_scale = iso_score_scale

    output_path = Path(best_model_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    bundle = {
        "dataset": "UNSW-NB15",
        "model_type": selected_type,
        "pipeline": selected_pipeline,
        "features": list(FLOW_FEATURES),
        "decision_threshold": float(selected_threshold),
        "score_scale": float(selected_score_scale),
        "validation_metrics": {
            "isolation_forest": val_iso_metrics,
            "random_forest": val_rf_metrics,
            "selected": selected_val_metrics,
        },
        "test_metrics": selected_test_metrics,
        "comparison": {
            "baseline_isolation_forest": test_iso_metrics,
            "random_forest": test_rf_metrics,
        },
    }
    joblib.dump(bundle, output_path)

    return {
        "best_model_path": output_path,
        "selected_model_type": selected_type,
        "decision_threshold": float(selected_threshold),
        "loaded_preserved_baseline": loaded_preserved_baseline,
        "train_split_rows": int(len(X_tr)),
        "val_split_rows": int(len(X_val)),
        "test_rows": int(len(X_test)),
        "validation_metrics": bundle["validation_metrics"],
        "baseline_test_metrics": test_iso_metrics,
        "random_forest_test_metrics": test_rf_metrics,
        "bundle": bundle,
    }


def print_comparison_report(result):
    """Print a side-by-side baseline vs improved UNSW-NB15 comparison report."""
    iso = result["baseline_test_metrics"]
    rf = result["random_forest_test_metrics"]

    print(f"Saved best UNSW-NB15 model ({result['selected_model_type']}) to: {result['best_model_path']}")
    print(
        f"Splits -> Train: {result['train_split_rows']} | "
        f"Validation (threshold tuning): {result['val_split_rows']} | "
        f"Test (single eval): {result['test_rows']}"
    )
    print(f"Validation-tuned RandomForest threshold: {result['decision_threshold']:.2f}\n")
    print("=== Test-Set Comparison: IsolationForest (Baseline) vs RandomForest (Improved) ===")
    print(f"{'Metric':<18} {'IsolationForest':>18} {'RandomForest':>18}")
    print("-" * 56)
    for key, label in (
        ("precision", "Precision"),
        ("recall", "Recall"),
        ("f1_score", "F1-Score"),
        ("roc_auc", "ROC-AUC"),
        ("pr_auc", "PR-AUC"),
    ):
        print(f"{label:<18} {iso[key]:>18.4f} {rf[key]:>18.4f}")

    print("\nConfusion Matrix — IsolationForest Baseline (TN, FP / FN, TP):")
    print(f"  Normal (0): TN={iso['tn']}, FP={iso['fp']}")
    print(f"  Attack (1): FN={iso['fn']}, TP={iso['tp']}")

    print("\nConfusion Matrix — RandomForestClassifier (TN, FP / FN, TP):")
    print(f"  Normal (0): TN={rf['tn']}, FP={rf['fp']}")
    print(f"  Attack (1): FN={rf['fn']}, TP={rf['tp']}")


def main():
    """CLI entry point for benchmarking UNSW-NB15 baseline vs RandomForest."""
    parser = argparse.ArgumentParser(description="Benchmark UNSW-NB15 IsolationForest vs RandomForest.")
    parser.add_argument("--train-csv", type=Path, default=DEFAULT_TRAIN_CSV)
    parser.add_argument("--test-csv", type=Path, default=DEFAULT_TEST_CSV)
    parser.add_argument("--baseline-model", type=Path, default=DEFAULT_UNSW_MODEL_PATH)
    parser.add_argument("--best-model", type=Path, default=DEFAULT_BEST_MODEL_PATH)
    parser.add_argument("--chunksize", type=int, default=25000)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    result = benchmark_and_save_best(
        train_csv=args.train_csv,
        test_csv=args.test_csv,
        baseline_model_path=args.baseline_model,
        best_model_path=args.best_model,
        chunksize=args.chunksize,
        n_estimators=args.n_estimators,
        random_state=args.seed,
    )
    print_comparison_report(result)


if __name__ == "__main__":
    main()

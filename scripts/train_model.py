"""Train and evaluate an IsolationForest anomaly detector for NetSentinel AI."""

import argparse
from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ml.feature_schema import (  # noqa: E402
    CATEGORICAL_FEATURES,
    FLOW_FEATURES,
    NUMERIC_FEATURES,
    validate_flow_dataframe,
)
from scripts.generate_demo_data import DEFAULT_DATA_DIR, generate_datasets  # noqa: E402

DEFAULT_MODEL_DIR = PROJECT_ROOT / "models"
DEFAULT_MODEL_FILENAME = "isolation_forest.joblib"


def build_preprocessor():
    """Build the shared ColumnTransformer for numeric and protocol flow features."""
    return ColumnTransformer(
        transformers=[
            ("numeric", StandardScaler(), NUMERIC_FEATURES),
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                CATEGORICAL_FEATURES,
            ),
        ],
        remainder="drop",
    )


def build_pipeline(contamination=0.02, n_estimators=200, random_state=42):
    """Build the preprocessing + IsolationForest scikit-learn pipeline."""
    detector = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )

    return Pipeline(
        steps=[
            ("preprocessor", build_preprocessor()),
            ("model", detector),
        ]
    )


def evaluate_model(pipeline, eval_benign_df, eval_anomalous_df):
    """Evaluate a trained IsolationForest pipeline on benign + anomalous flows.

    Returns a dictionary with precision, recall, f1_score, and confusion_matrix.
    """
    benign_x = validate_flow_dataframe(eval_benign_df)
    anomalous_x = validate_flow_dataframe(eval_anomalous_df)

    eval_x = pd.concat([benign_x, anomalous_x], ignore_index=True)
    y_true = np.concatenate(
        [
            np.zeros(len(benign_x), dtype=int),
            np.ones(len(anomalous_x), dtype=int),
        ]
    )

    raw_preds = pipeline.predict(eval_x)
    # IsolationForest returns -1 for anomaly, 1 for normal.
    y_pred = np.where(raw_preds == -1, 1, 0)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))

    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": cm.tolist(),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "total_eval_samples": int(len(eval_x)),
    }


def print_evaluation_report(metrics):
    """Print clear precision, recall, and confusion-matrix evaluation output."""
    print("\n=== Synthetic Evaluation Results ===")
    print(f"Samples Evaluated : {metrics['total_eval_samples']}")
    print(f"Precision         : {metrics['precision']:.4f}")
    print(f"Recall            : {metrics['recall']:.4f}")
    print(f"F1-Score          : {metrics['f1_score']:.4f}")
    print("\nConfusion Matrix (rows = Actual, cols = Predicted):")
    print("                  Pred Benign (0)   Pred Anomaly (1)")
    print(f"Actual Benign (0)     {metrics['tn']:>8d}          {metrics['fp']:>8d}")
    print(f"Actual Anomaly (1)    {metrics['fn']:>8d}          {metrics['tp']:>8d}")


def train_and_save_model(
    data_dir=DEFAULT_DATA_DIR,
    model_dir=DEFAULT_MODEL_DIR,
    model_filename=DEFAULT_MODEL_FILENAME,
    contamination=0.02,
    n_estimators=200,
    random_state=42,
):
    """Train IsolationForest strictly on benign flows, evaluate it, and save with joblib."""
    data_path = Path(data_dir)
    train_path = data_path / "benign_train.csv"
    eval_benign_path = data_path / "benign_eval.csv"
    eval_anomalous_path = data_path / "anomalous_eval.csv"

    if not (train_path.exists() and eval_benign_path.exists() and eval_anomalous_path.exists()):
        generate_datasets(output_dir=data_path, random_state=random_state)

    train_df = validate_flow_dataframe(pd.read_csv(train_path))
    eval_benign_df = validate_flow_dataframe(pd.read_csv(eval_benign_path))
    eval_anomalous_df = validate_flow_dataframe(pd.read_csv(eval_anomalous_path))

    # Train strictly on benign flows only.
    pipeline = build_pipeline(
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_state,
    )
    pipeline.fit(train_df[FLOW_FEATURES])

    train_scores = pipeline.decision_function(train_df[FLOW_FEATURES])
    score_scale = float(max(np.std(train_scores), 0.05))

    metrics = evaluate_model(pipeline, eval_benign_df, eval_anomalous_df)

    model_output_dir = Path(model_dir)
    model_output_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_output_dir / model_filename

    bundle = {
        "pipeline": pipeline,
        "features": list(FLOW_FEATURES),
        "score_scale": score_scale,
        "contamination": contamination,
        "n_estimators": n_estimators,
        "random_state": random_state,
        "evaluation_metrics": metrics,
    }
    joblib.dump(bundle, model_path)

    return {
        "model_path": model_path,
        "bundle": bundle,
        "metrics": metrics,
    }


def main():
    """CLI entry point for model training and evaluation."""
    parser = argparse.ArgumentParser(description="Train NetSentinel AI IsolationForest model.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    result = train_and_save_model(
        data_dir=args.data_dir,
        model_dir=args.model_dir,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=args.seed,
    )
    print(f"Saved trained preprocessing + IsolationForest pipeline to: {result['model_path']}")
    print_evaluation_report(result["metrics"])


if __name__ == "__main__":
    main()

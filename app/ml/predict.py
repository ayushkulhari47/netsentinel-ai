"""Reusable inference utilities for NetSentinel AI anomaly detection."""

import math
from pathlib import Path
import joblib
import pandas as pd
from app.ml.feature_schema import (
    FLOW_FEATURES,
    validate_flow_dataframe,
    validate_flow_record,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest.joblib"


def load_model_bundle(model_path=DEFAULT_MODEL_PATH):
    """Load the saved preprocessing + IsolationForest bundle via joblib."""
    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Trained model file not found at '{path}'. "
            "Run 'python scripts/train_model.py' first."
        )

    loaded = joblib.load(path)
    if isinstance(loaded, dict) and "pipeline" in loaded:
        return loaded

    return {
        "pipeline": loaded,
        "features": list(FLOW_FEATURES),
        "score_scale": 0.1,
    }


def _score_to_result(decision_score, raw_pred, score_scale):
    """Convert raw IsolationForest outputs into anomaly_score, prediction, and confidence."""
    anomaly_score = round(float(-decision_score), 4)
    prediction = "anomaly" if int(raw_pred) == -1 else "normal"
    scale = max(float(score_scale), 1e-6)
    confidence = round(float(0.5 + 0.5 * math.tanh(abs(float(decision_score)) / scale)), 4)

    return {
        "anomaly_score": anomaly_score,
        "prediction": prediction,
        "confidence": confidence,
    }


def predict_flows(flows, model_path=DEFAULT_MODEL_PATH, model_bundle=None):
    """Predict anomaly scores, labels, and confidence for a batch of network flows."""
    bundle = model_bundle if model_bundle is not None else load_model_bundle(model_path)
    pipeline = bundle["pipeline"]
    score_scale = bundle.get("score_scale", 0.1)

    if isinstance(flows, pd.DataFrame):
        df = validate_flow_dataframe(flows)
    elif isinstance(flows, list):
        if not flows:
            raise ValueError("flows list must not be empty.")
        validated = [validate_flow_record(row) for row in flows]
        df = pd.DataFrame(validated, columns=FLOW_FEATURES)
    else:
        raise ValueError("flows must be a list of dictionaries or a pandas DataFrame.")

    decision_scores = pipeline.decision_function(df[FLOW_FEATURES])
    raw_preds = pipeline.predict(df[FLOW_FEATURES])

    return [
        _score_to_result(score, pred, score_scale)
        for score, pred in zip(decision_scores, raw_preds)
    ]


def predict_flow(flow_data, model_path=DEFAULT_MODEL_PATH, model_bundle=None):
    """Predict anomaly score, prediction label, and confidence for a single network flow.

    Returns a dictionary with keys:
      - anomaly_score (float): positive values indicate stronger anomaly likelihood
      - prediction (str): "anomaly" or "normal"
      - confidence (float): confidence score between 0.5 and 1.0
    """
    cleaned = validate_flow_record(flow_data)
    results = predict_flows([cleaned], model_path=model_path, model_bundle=model_bundle)
    return results[0]

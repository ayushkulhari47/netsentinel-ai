"""Reusable inference utilities for NetSentinel AI anomaly detection."""

import math
import os
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


def get_default_model_path():
    """Resolve the active ML model path from ML_MODEL_PATH or fallback default."""
    configured = os.environ.get("ML_MODEL_PATH")
    if isinstance(configured, str) and configured.strip():
        candidate = Path(configured.strip())
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate
    return DEFAULT_MODEL_PATH


def load_model_bundle(model_path=None):
    """Load the saved preprocessing + IsolationForest bundle via joblib."""
    path = Path(model_path) if model_path is not None else get_default_model_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Trained model file not found at '{path}'. "
            "Run 'python scripts/train_model.py' or 'python scripts/train_unsw_model.py' first."
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


def _proba_to_result(prob_attack, threshold):
    """Convert supervised attack probability and decision threshold into standard output."""
    prob = max(0.0, min(1.0, float(prob_attack)))
    thresh = max(1e-6, min(1.0 - 1e-6, float(threshold)))
    is_anomaly = prob >= thresh

    if is_anomaly:
        confidence = 0.5 + 0.5 * ((prob - thresh) / max(1.0 - thresh, 1e-6))
    else:
        confidence = 0.5 + 0.5 * ((thresh - prob) / max(thresh, 1e-6))

    return {
        "anomaly_score": round(prob, 4),
        "prediction": "anomaly" if is_anomaly else "normal",
        "confidence": round(min(1.0, max(0.5, confidence)), 4),
    }


def _is_supervised_classifier(bundle, pipeline):
    """Return True if the loaded model bundle represents a supervised classifier."""
    model_type = str(bundle.get("model_type", "")).strip().lower()
    if model_type == "random_forest":
        return True
    if model_type == "isolation_forest":
        return False
    return hasattr(pipeline, "predict_proba")


def predict_flows(flows, model_path=None, model_bundle=None):
    """Predict anomaly scores, labels, and confidence for a batch of network flows."""
    bundle = model_bundle if model_bundle is not None else load_model_bundle(model_path)
    pipeline = bundle["pipeline"]
    score_scale = bundle.get("score_scale", 0.1)
    features = bundle.get("features") or FLOW_FEATURES

    if isinstance(flows, pd.DataFrame):
        df = validate_flow_dataframe(flows)
    elif isinstance(flows, list):
        if not flows:
            raise ValueError("flows list must not be empty.")
        validated = [validate_flow_record(row) for row in flows]
        df = pd.DataFrame(validated, columns=FLOW_FEATURES)
    else:
        raise ValueError("flows must be a list of dictionaries or a pandas DataFrame.")

    if _is_supervised_classifier(bundle, pipeline):
        threshold = float(bundle.get("decision_threshold", 0.5))
        probs = pipeline.predict_proba(df[features])[:, 1]
        return [_proba_to_result(prob, threshold) for prob in probs]

    decision_scores = pipeline.decision_function(df[features])
    raw_preds = pipeline.predict(df[features])

    return [
        _score_to_result(score, pred, score_scale)
        for score, pred in zip(decision_scores, raw_preds)
    ]


def predict_flow(flow_data, model_path=None, model_bundle=None):
    """Predict anomaly score, prediction label, and confidence for a single network flow.

    Returns a dictionary with keys:
      - anomaly_score (float): positive values indicate stronger anomaly likelihood
      - prediction (str): "anomaly" or "normal"
      - confidence (float): confidence score between 0.5 and 1.0
    """
    cleaned = validate_flow_record(flow_data)
    results = predict_flows([cleaned], model_path=model_path, model_bundle=model_bundle)
    return results[0]

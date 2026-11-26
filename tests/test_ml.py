"""Tests for ML feature validation, dataset generation, training, and prediction."""

import numpy as np
import pandas as pd
import pytest

from app.ml.feature_schema import (
    FLOW_FEATURES,
    validate_flow_dataframe,
    validate_flow_record,
)
from app.ml.predict import predict_flow, predict_flows
from scripts.generate_demo_data import generate_datasets
from scripts.train_model import train_and_save_model


def _sample_benign_flow():
    """Return a realistic benign HTTPS flow matching FLOW_FEATURES."""
    return {
        "duration": 2.5,
        "protocol": "TCP",
        "source_port": 54321,
        "destination_port": 443,
        "flow_bytes": 18000.0,
        "flow_packets": 30,
        "forward_packets": 14,
        "backward_packets": 16,
        "average_packet_size": 600.0,
        "packet_rate": 12.0,
        "byte_rate": 7200.0,
    }


def _sample_anomalous_flow():
    """Return a high-rate SYN flood anomalous flow matching FLOW_FEATURES."""
    return {
        "duration": 0.2,
        "protocol": "TCP",
        "source_port": 23456,
        "destination_port": 80,
        "flow_bytes": 144000.0,
        "flow_packets": 2400,
        "forward_packets": 2400,
        "backward_packets": 0,
        "average_packet_size": 60.0,
        "packet_rate": 12000.0,
        "byte_rate": 720000.0,
    }


def test_flow_features_schema_exact_list():
    """FLOW_FEATURES should contain the exact 11 standard network flow features."""
    assert FLOW_FEATURES == [
        "duration",
        "protocol",
        "source_port",
        "destination_port",
        "flow_bytes",
        "flow_packets",
        "forward_packets",
        "backward_packets",
        "average_packet_size",
        "packet_rate",
        "byte_rate",
    ]


def test_validate_flow_record_normalizes_valid_input():
    """validate_flow_record should normalize protocol and numeric types."""
    record = _sample_benign_flow()
    record["protocol"] = 6  # IANA TCP protocol number
    record["source_port"] = np.int64(51000)

    cleaned = validate_flow_record(record)
    assert cleaned["protocol"] == "TCP"
    assert isinstance(cleaned["source_port"], int)
    assert cleaned["source_port"] == 51000
    assert list(cleaned.keys()) == FLOW_FEATURES


@pytest.mark.parametrize(
    "mutator",
    [
        lambda r: r.pop("byte_rate"),
        lambda r: r.update({"duration": -1.0}),
        lambda r: r.update({"flow_bytes": float("nan")}),
        lambda r: r.update({"source_port": 70000}),
        lambda r: r.update({"destination_port": 443.5}),
        lambda r: r.update({"flow_packets": True}),
        lambda r: r.update({"protocol": ""}),
        lambda r: r.update({"protocol": "UNKNOWN_PROTO"}),
    ],
)
def test_validate_flow_record_rejects_invalid_values(mutator):
    """validate_flow_record should raise ValueError on missing or invalid values."""
    record = _sample_benign_flow()
    mutator(record)
    with pytest.raises(ValueError):
        validate_flow_record(record)


def test_validate_flow_dataframe_checks_columns_and_non_empty():
    """validate_flow_dataframe should validate columns, rows, and reject empty inputs."""
    df = pd.DataFrame([_sample_benign_flow()])
    cleaned_df = validate_flow_dataframe(df)
    assert list(cleaned_df.columns) == FLOW_FEATURES
    assert len(cleaned_df) == 1

    with pytest.raises(ValueError):
        validate_flow_dataframe(pd.DataFrame(columns=FLOW_FEATURES))

    with pytest.raises(ValueError):
        validate_flow_dataframe(df.drop(columns=["packet_rate"]))


def test_train_evaluate_and_predict_end_to_end(tmp_path):
    """Training on benign data should save a joblib bundle and detect anomalies."""
    data_dir = tmp_path / "data"
    model_dir = tmp_path / "models"

    datasets = generate_datasets(
        output_dir=data_dir,
        train_samples=400,
        eval_benign_samples=100,
        eval_anomaly_samples=100,
        random_state=42,
    )
    assert datasets["train_benign_path"].exists()
    assert datasets["eval_benign_path"].exists()
    assert datasets["eval_anomalous_path"].exists()

    train_result = train_and_save_model(
        data_dir=data_dir,
        model_dir=model_dir,
        contamination=0.02,
        n_estimators=100,
        random_state=42,
    )
    model_path = train_result["model_path"]
    metrics = train_result["metrics"]

    assert model_path.exists()
    assert model_path.suffix == ".joblib"
    assert metrics["total_eval_samples"] == 200
    assert metrics["precision"] >= 0.85
    assert metrics["recall"] >= 0.90

    cm = metrics["confusion_matrix"]
    assert len(cm) == 2 and len(cm[0]) == 2
    assert sum(sum(row) for row in cm) == 200

    benign_pred = predict_flow(_sample_benign_flow(), model_path=model_path)
    assert set(benign_pred.keys()) == {"anomaly_score", "prediction", "confidence"}
    assert benign_pred["prediction"] == "normal"
    assert 0.5 <= benign_pred["confidence"] <= 1.0

    anomaly_pred = predict_flow(_sample_anomalous_flow(), model_path=model_path)
    assert set(anomaly_pred.keys()) == {"anomaly_score", "prediction", "confidence"}
    assert anomaly_pred["prediction"] == "anomaly"
    assert anomaly_pred["anomaly_score"] > benign_pred["anomaly_score"]
    assert 0.5 <= anomaly_pred["confidence"] <= 1.0

    batch_preds = predict_flows(
        [_sample_benign_flow(), _sample_anomalous_flow()],
        model_path=model_path,
    )
    assert len(batch_preds) == 2
    assert batch_preds[0]["prediction"] == "normal"
    assert batch_preds[1]["prediction"] == "anomaly"


def test_predict_flow_raises_when_model_missing(tmp_path):
    """predict_flow should raise FileNotFoundError if model artifact does not exist."""
    missing_model = tmp_path / "does_not_exist.joblib"
    with pytest.raises(FileNotFoundError):
        predict_flow(_sample_benign_flow(), model_path=missing_model)

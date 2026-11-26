"""Unit tests for UNSW-NB15 benchmarking and RandomForest inference support."""

import joblib
import pandas as pd
import pytest

from app import create_app
from app.ml.feature_schema import FLOW_FEATURES
from app.ml.predict import predict_flow, predict_flows
from app.services.detection_engine import DetectionEngine
from scripts.benchmark_unsw_models import (
    benchmark_and_save_best,
    build_random_forest_pipeline,
)


def _make_unsw_fixture_df(n_normal=20, n_attack=10, offset=0):
    """Create a small deterministic UNSW-NB15-style DataFrame."""
    rows = []
    for idx in range(n_normal):
        rows.append(
            {
                "id": offset + idx + 1,
                "dur": 0.8 + (idx % 4) * 0.25,
                "proto": "tcp" if idx % 2 == 0 else "udp",
                "service": "http" if idx % 2 == 0 else "dns",
                "spkts": 6 + (idx % 3),
                "dpkts": 6 + (idx % 3),
                "sbytes": 500 + idx * 10,
                "dbytes": 900 + idx * 15,
                "rate": 14.0 + (idx % 5),
                "sload": 5000.0,
                "dload": 9000.0,
                "attack_cat": "Normal",
                "label": 0,
            }
        )
    for idx in range(n_attack):
        rows.append(
            {
                "id": offset + 1000 + idx,
                "dur": 0.01,
                "proto": "tcp",
                "service": "-",
                "spkts": 1800 + idx * 20,
                "dpkts": 0,
                "sbytes": 120000 + idx * 1000,
                "dbytes": 0,
                "rate": 180000.0,
                "sload": 96000000.0,
                "dload": 0.0,
                "attack_cat": "DoS",
                "label": 1,
            }
        )
    return pd.DataFrame(rows)


def test_benchmark_compares_models_and_saves_best_bundle(tmp_path):
    """Benchmark should tune threshold on validation split, evaluate test once, and save bundle."""
    train_csv = tmp_path / "train.csv"
    test_csv = tmp_path / "test.csv"
    best_model_path = tmp_path / "models" / "unsw_best_model.joblib"
    missing_baseline = tmp_path / "models" / "no_baseline.joblib"

    _make_unsw_fixture_df(n_normal=30, n_attack=15, offset=0).to_csv(train_csv, index=False)
    _make_unsw_fixture_df(n_normal=10, n_attack=10, offset=500).to_csv(test_csv, index=False)

    result = benchmark_and_save_best(
        train_csv=train_csv,
        test_csv=test_csv,
        baseline_model_path=missing_baseline,
        best_model_path=best_model_path,
        chunksize=10,
        n_estimators=25,
        val_size=0.2,
        random_state=42,
    )

    assert best_model_path.exists()
    assert result["train_split_rows"] == 36
    assert result["val_split_rows"] == 9
    assert result["test_rows"] == 20
    assert result["loaded_preserved_baseline"] is False

    bundle = joblib.load(best_model_path)
    assert bundle["model_type"] in {"random_forest", "isolation_forest"}
    assert bundle["features"] == FLOW_FEATURES
    assert "decision_threshold" in bundle
    assert "label" not in bundle["features"]
    assert "attack_cat" not in bundle["features"]
    assert "id" not in bundle["features"]

    if bundle["model_type"] == "random_forest":
        clf = bundle["pipeline"].named_steps["model"]
        assert clf.class_weight == "balanced_subsample"

    for metrics_key in ("baseline_test_metrics", "random_forest_test_metrics"):
        m = result[metrics_key]
        for field in ("precision", "recall", "f1_score", "roc_auc", "pr_auc", "confusion_matrix"):
            assert field in m
        assert sum(sum(row) for row in m["confusion_matrix"]) == 20


def test_predict_flow_supports_random_forest_and_detection_engine(tmp_path):
    """predict_flow, predict_flows, and DetectionEngine should support RandomForest bundles."""
    rf_pipeline = build_random_forest_pipeline(n_estimators=20, random_state=42, n_jobs=1)
    assert rf_pipeline.named_steps["model"].class_weight == "balanced_subsample"

    normal_row = {
        "duration": 1.0,
        "protocol": "TCP",
        "source_port": 0,
        "destination_port": 80,
        "flow_bytes": 1400.0,
        "flow_packets": 12.0,
        "forward_packets": 6.0,
        "backward_packets": 6.0,
        "average_packet_size": 116.67,
        "packet_rate": 12.0,
        "byte_rate": 1400.0,
    }
    attack_row = {
        "duration": 0.01,
        "protocol": "TCP",
        "source_port": 0,
        "destination_port": 0,
        "flow_bytes": 150000.0,
        "flow_packets": 2000.0,
        "forward_packets": 2000.0,
        "backward_packets": 0.0,
        "average_packet_size": 75.0,
        "packet_rate": 200000.0,
        "byte_rate": 15000000.0,
    }

    train_X = pd.DataFrame([normal_row] * 8 + [attack_row] * 8, columns=FLOW_FEATURES)
    train_y = [0] * 8 + [1] * 8
    rf_pipeline.fit(train_X, train_y)

    bundle_path = tmp_path / "unsw_best_model.joblib"
    joblib.dump(
        {
            "dataset": "UNSW-NB15",
            "model_type": "random_forest",
            "pipeline": rf_pipeline,
            "features": list(FLOW_FEATURES),
            "decision_threshold": 0.45,
        },
        bundle_path,
    )

    single_normal = predict_flow(normal_row, model_path=bundle_path)
    assert set(single_normal.keys()) == {"anomaly_score", "prediction", "confidence"}
    assert single_normal["prediction"] == "normal"
    assert 0.5 <= single_normal["confidence"] <= 1.0

    batch = predict_flows([normal_row, attack_row], model_path=bundle_path)
    assert batch[0]["prediction"] == "normal"
    assert batch[1]["prediction"] == "anomaly"
    assert batch[1]["anomaly_score"] > batch[0]["anomaly_score"]

    # DetectionEngine integration using ML_MODEL_PATH
    db_file = tmp_path / "rf_det.db"
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
            "ML_MODEL_PATH": str(bundle_path),
        }
    )
    with app.app_context():
        engine = DetectionEngine()
        res = engine.analyze_flow(
            {**attack_row, "source_ip": "198.51.100.77", "destination_ip": "10.0.0.5"},
            persist=True,
        )
        assert res["ml_available"] is True
        assert res["is_suspicious"] is True
        assert res["alert"] is not None

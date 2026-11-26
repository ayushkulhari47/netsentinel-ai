"""Unit tests for UNSW-NB15 column mapping, chunked training, and ML_MODEL_PATH."""

import pandas as pd
import pytest

from app import create_app
from app.ml.feature_schema import FLOW_FEATURES, validate_flow_dataframe
from app.ml.predict import DEFAULT_MODEL_PATH, get_default_model_path, predict_flow
from app.services.detection_engine import DetectionEngine
from scripts.train_unsw_model import (
    load_unsw_training_benign_features,
    map_unsw_chunk_to_flow_features,
    train_and_evaluate_unsw,
)


def test_map_unsw_chunk_handles_missing_dash_invalid_ports_and_unknown_protocols():
    """Mapper should sanitize '-', NaNs, bad ports, unknown protocols, and pass schema check."""
    raw_df = pd.DataFrame(
        [
            {
                "id": 1,
                "dur": 0.5,
                "proto": "tcp",
                "sport": "54321",
                "dsport": "0x0050",  # hex 80
                "sbytes": 500,
                "dbytes": 1000,
                "spkts": 5,
                "dpkts": 5,
                "rate": 18.0,
                "sload": 8000.0,
                "dload": 16000.0,
                "label": 0,
                "attack_cat": "Normal",
            },
            {
                "id": 2,
                "dur": "-",
                "proto": "unas",
                "sport": "99999",
                "dsport": "-",
                "sbytes": "-",
                "dbytes": None,
                "spkts": 2,
                "dpkts": "-",
                "rate": "-",
                "sload": "-",
                "dload": None,
                "label": 1,
                "attack_cat": "Fuzzers",
            },
            {
                "id": 3,
                "dur": 0.0,
                "proto": "-",
                "sport": "not-a-port",
                "dsport": -1,
                "sbytes": 120,
                "dbytes": 0,
                "spkts": 1,
                "dpkts": 0,
                "rate": 0.0,
                "sload": 0.0,
                "dload": 0.0,
                "label": 0,
                "attack_cat": "Normal",
            },
        ]
    )

    mapped = map_unsw_chunk_to_flow_features(raw_df)
    assert list(mapped.columns) == FLOW_FEATURES
    assert "label" not in mapped.columns
    assert "attack_cat" not in mapped.columns

    # Row 0: valid TCP + hex port + sload/dload conversion
    assert mapped.loc[0, "protocol"] == "TCP"
    assert mapped.loc[0, "source_port"] == 54321
    assert mapped.loc[0, "destination_port"] == 80
    assert mapped.loc[0, "flow_bytes"] == 1500.0
    assert mapped.loc[0, "flow_packets"] == 10.0
    assert mapped.loc[0, "average_packet_size"] == 150.0
    assert mapped.loc[0, "packet_rate"] == 18.0
    assert mapped.loc[0, "byte_rate"] == 3000.0

    # Row 1 & 2: '-' / invalid / unknown safely normalized
    assert mapped.loc[1, "protocol"] == "OTHER"
    assert mapped.loc[1, "source_port"] == 0
    assert mapped.loc[1, "destination_port"] == 0
    assert mapped.loc[1, "duration"] == 0.0
    assert mapped.loc[1, "flow_bytes"] == 0.0
    assert mapped.loc[2, "protocol"] == "OTHER"
    assert mapped.loc[2, "source_port"] == 0
    assert mapped.loc[2, "destination_port"] == 0

    validated = validate_flow_dataframe(mapped)
    assert len(validated) == 3


def test_map_unsw_infers_destination_port_from_service_when_dsport_absent():
    """When dsport is omitted (as in UNSW training-set/testing-set), service maps standard ports."""
    raw_df = pd.DataFrame(
        [
            {
                "dur": 0.2,
                "proto": "udp",
                "service": "dns",
                "spkts": 2,
                "dpkts": 2,
                "sbytes": 120,
                "dbytes": 240,
                "rate": 15.0,
                "sload": 4000.0,
                "dload": 8000.0,
            },
            {
                "dur": 1.0,
                "proto": "tcp",
                "service": "-",
                "spkts": 4,
                "dpkts": 4,
                "sbytes": 400,
                "dbytes": 800,
                "rate": 7.0,
                "sload": 3200.0,
                "dload": 6400.0,
            },
        ]
    )

    mapped = map_unsw_chunk_to_flow_features(raw_df)
    assert mapped.loc[0, "source_port"] == 0
    assert mapped.loc[0, "destination_port"] == 53
    assert mapped.loc[1, "destination_port"] == 0


def test_train_and_evaluate_unsw_with_small_chunked_csv_fixtures(tmp_path):
    """train_and_evaluate_unsw should train only on label==0 in chunks and evaluate test set."""
    train_rows = []
    for idx in range(12):
        train_rows.append(
            {
                "id": idx + 1,
                "dur": 0.5 + (idx % 3) * 0.2,
                "proto": "tcp" if idx % 2 == 0 else "udp",
                "service": "http" if idx % 2 == 0 else "dns",
                "spkts": 6 + (idx % 4),
                "dpkts": 6 + (idx % 3),
                "sbytes": 400 + idx * 10,
                "dbytes": 600 + idx * 15,
                "rate": 15.0 + idx,
                "sload": 6400.0,
                "dload": 9600.0,
                "attack_cat": "Normal",
                "label": 0,
            }
        )
    # Include attack rows in training CSV that MUST be excluded from benign training
    for idx in range(4):
        train_rows.append(
            {
                "id": 100 + idx,
                "dur": 0.01,
                "proto": "tcp",
                "service": "-",
                "spkts": 2000,
                "dpkts": 0,
                "sbytes": 120000,
                "dbytes": 0,
                "rate": 200000.0,
                "sload": 96000000.0,
                "dload": 0.0,
                "attack_cat": "DoS",
                "label": 1,
            }
        )

    test_rows = [
        {
            "id": 1,
            "dur": 0.6,
            "proto": "tcp",
            "service": "http",
            "spkts": 7,
            "dpkts": 7,
            "sbytes": 450,
            "dbytes": 700,
            "rate": 18.0,
            "sload": 6400.0,
            "dload": 9600.0,
            "attack_cat": "Normal",
            "label": 0,
        },
        {
            "id": 2,
            "dur": 0.5,
            "proto": "udp",
            "service": "dns",
            "spkts": 6,
            "dpkts": 6,
            "sbytes": 410,
            "dbytes": 615,
            "rate": 16.0,
            "sload": 6400.0,
            "dload": 9600.0,
            "attack_cat": "Normal",
            "label": 0,
        },
        {
            "id": 3,
            "dur": 0.01,
            "proto": "tcp",
            "service": "-",
            "spkts": 2500,
            "dpkts": 0,
            "sbytes": 150000,
            "dbytes": 0,
            "rate": 250000.0,
            "sload": 120000000.0,
            "dload": 0.0,
            "attack_cat": "DoS",
            "label": 1,
        },
        {
            "id": 4,
            "dur": 0.005,
            "proto": "unas",
            "service": "-",
            "spkts": 1500,
            "dpkts": 0,
            "sbytes": 90000,
            "dbytes": 0,
            "rate": 300000.0,
            "sload": 144000000.0,
            "dload": 0.0,
            "attack_cat": "Reconnaissance",
            "label": 1,
        },
    ]

    train_csv = tmp_path / "train.csv"
    test_csv = tmp_path / "test.csv"
    model_path = tmp_path / "models" / "isolation_forest_unsw_nb15.joblib"

    pd.DataFrame(train_rows).to_csv(train_csv, index=False)
    pd.DataFrame(test_rows).to_csv(test_csv, index=False)

    # Verify chunked benign loader excludes label==1
    benign_df = load_unsw_training_benign_features(train_csv, chunksize=3)
    assert len(benign_df) == 12

    result = train_and_evaluate_unsw(
        train_csv=train_csv,
        test_csv=test_csv,
        model_path=model_path,
        chunksize=3,
        contamination=0.05,
        n_estimators=50,
        random_state=42,
    )

    assert model_path.exists()
    metrics = result["metrics"]
    assert metrics["benign_training_rows"] == 12
    assert metrics["test_rows"] == 4
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert sum(sum(r) for r in metrics["confusion_matrix"]) == 4
    assert set(metrics["attack_categories"]) == {"DoS", "Reconnaissance"}
    assert result["bundle"]["features"] == FLOW_FEATURES

    # Trained UNSW model works with predict_flow
    pred = predict_flow(
        {
            "duration": 0.01,
            "protocol": "TCP",
            "source_port": 0,
            "destination_port": 0,
            "flow_bytes": 150000.0,
            "flow_packets": 2500,
            "forward_packets": 2500,
            "backward_packets": 0,
            "average_packet_size": 60.0,
            "packet_rate": 250000.0,
            "byte_rate": 15000000.0,
        },
        model_path=model_path,
    )
    assert pred["prediction"] == "anomaly"


def test_ml_model_path_configuration(tmp_path, monkeypatch):
    """ML_MODEL_PATH env var and Flask app.config should control active model selection."""
    monkeypatch.delenv("ML_MODEL_PATH", raising=False)
    assert get_default_model_path() == DEFAULT_MODEL_PATH

    custom_model = tmp_path / "custom_unsw.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(custom_model))
    assert get_default_model_path() == custom_model

    db_file = tmp_path / "test_cfg.db"
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
            "ML_MODEL_PATH": str(custom_model),
        }
    )
    with app.app_context():
        assert app.config["ML_MODEL_PATH"] == str(custom_model)
        engine = DetectionEngine()
        assert engine._resolve_model_path() == str(custom_model)

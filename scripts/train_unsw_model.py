"""Train and evaluate an IsolationForest model on the UNSW-NB15 dataset."""

import argparse
from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ml.feature_schema import ALLOWED_PROTOCOLS, FLOW_FEATURES  # noqa: E402
from scripts.train_model import build_pipeline  # noqa: E402

DEFAULT_UNSW_DIR = PROJECT_ROOT / "data" / "raw" / "UNSW-NB15"
DEFAULT_TRAIN_CSV = DEFAULT_UNSW_DIR / "UNSW_NB15_training-set.csv"
DEFAULT_TEST_CSV = DEFAULT_UNSW_DIR / "UNSW_NB15_testing-set.csv"
DEFAULT_UNSW_MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest_unsw_nb15.joblib"

SERVICE_PORT_MAP = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "smtp": 25,
    "dns": 53,
    "dhcp": 67,
    "http": 80,
    "pop3": 110,
    "snmp": 161,
    "ssl": 443,
    "https": 443,
    "radius": 1812,
    "irc": 6667,
}


def _to_non_negative_float_series(series, default=0.0):
    """Coerce a Series (handling '-', blanks, NaNs, and infinities) to finite floats >= 0."""
    cleaned = series.replace(["-", "", " ", "nan", "NaN", "None"], np.nan)
    numeric = pd.to_numeric(cleaned, errors="coerce").replace([np.inf, -np.inf], np.nan)
    return numeric.fillna(default).clip(lower=0.0).astype(float)


def _parse_single_port(value):
    """Parse a decimal or hex port string/number safely into 0-65535, else 0."""
    if pd.isna(value):
        return 0
    raw = str(value).strip()
    if not raw or raw == "-":
        return 0
    try:
        if raw.lower().startswith("0x"):
            port = int(raw, 16)
        else:
            float_val = float(raw)
            if not np.isfinite(float_val) or not float_val.is_integer():
                return 0
            port = int(float_val)
    except (ValueError, OverflowError):
        return 0
    return port if 0 <= port <= 65535 else 0


def _normalize_unsw_protocol(series):
    """Map UNSW-NB15 proto values to ALLOWED_PROTOCOLS, using OTHER for unknown/missing."""
    tokens = (
        series.fillna("OTHER")
        .astype(str)
        .str.strip()
        .str.upper()
        .replace({"": "OTHER", "-": "OTHER"})
    )
    return tokens.where(tokens.isin(ALLOWED_PROTOCOLS), "OTHER")


def map_unsw_chunk_to_flow_features(chunk):
    """Map a raw UNSW-NB15 DataFrame chunk into canonical FLOW_FEATURES columns.

    Target columns (label, attack_cat, id) are never included in the returned features.
    Missing values, '-' placeholders, invalid ports, and unknown protocols are handled safely.
    """
    df = chunk.copy()
    df.columns = [str(col).strip().lower() for col in df.columns]
    n_rows = len(df)

    def _col_or_default(name, default_val=np.nan):
        if name in df.columns:
            return df[name]
        return pd.Series([default_val] * n_rows, index=df.index)

    duration = _to_non_negative_float_series(_col_or_default("dur", 0.0), default=0.0)
    protocol = _normalize_unsw_protocol(_col_or_default("proto", "OTHER"))

    if "sport" in df.columns:
        source_port = df["sport"].map(_parse_single_port).astype(int)
    else:
        source_port = pd.Series(np.zeros(n_rows, dtype=int), index=df.index)

    if "dsport" in df.columns:
        destination_port = df["dsport"].map(_parse_single_port).astype(int)
    elif "service" in df.columns:
        service_tokens = (
            df["service"].fillna("-").astype(str).str.strip().str.lower()
        )
        destination_port = service_tokens.map(SERVICE_PORT_MAP).fillna(0).astype(int)
    else:
        destination_port = pd.Series(np.zeros(n_rows, dtype=int), index=df.index)

    sbytes = _to_non_negative_float_series(_col_or_default("sbytes", 0.0), default=0.0)
    dbytes = _to_non_negative_float_series(_col_or_default("dbytes", 0.0), default=0.0)
    flow_bytes = np.round(sbytes + dbytes, 4)

    spkts = _to_non_negative_float_series(_col_or_default("spkts", 0.0), default=0.0)
    dpkts = _to_non_negative_float_series(_col_or_default("dpkts", 0.0), default=0.0)
    flow_packets = np.round(spkts + dpkts, 4)

    average_packet_size = np.where(
        flow_packets > 0.0,
        np.round(flow_bytes / np.maximum(flow_packets, 1.0), 4),
        0.0,
    )

    if "rate" in df.columns:
        raw_rate = pd.to_numeric(
            df["rate"].replace(["-", "", " "], np.nan), errors="coerce"
        ).replace([np.inf, -np.inf], np.nan)
        derived_rate = np.where(
            duration > 0.0,
            flow_packets / np.maximum(duration, 1e-9),
            0.0,
        )
        packet_rate = np.round(
            raw_rate.where(raw_rate.notna() & (raw_rate >= 0.0), derived_rate).astype(float),
            4,
        )
    else:
        packet_rate = np.where(
            duration > 0.0,
            np.round(flow_packets / np.maximum(duration, 1e-9), 4),
            0.0,
        )

    sload = _to_non_negative_float_series(_col_or_default("sload", np.nan), default=0.0)
    dload = _to_non_negative_float_series(_col_or_default("dload", np.nan), default=0.0)
    load_byte_rate = (sload + dload) / 8.0
    fallback_byte_rate = np.where(
        duration > 0.0,
        flow_bytes / np.maximum(duration, 1e-9),
        0.0,
    )
    has_load_fields = ("sload" in df.columns) or ("dload" in df.columns)
    byte_rate = np.round(
        np.where(
            has_load_fields & ((load_byte_rate > 0.0) | (duration <= 0.0)),
            load_byte_rate,
            fallback_byte_rate,
        ),
        4,
    )

    return pd.DataFrame(
        {
            "duration": duration,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "flow_bytes": flow_bytes,
            "flow_packets": flow_packets,
            "forward_packets": spkts,
            "backward_packets": dpkts,
            "average_packet_size": average_packet_size,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
        },
        columns=FLOW_FEATURES,
    )


def load_unsw_training_benign_features(train_csv, chunksize=25000):
    """Load and map only benign (label == 0) rows from the UNSW-NB15 training CSV in chunks."""
    train_path = Path(train_csv)
    if not train_path.exists():
        raise FileNotFoundError(f"UNSW-NB15 training CSV not found: {train_path}")

    benign_chunks = []
    for chunk in pd.read_csv(train_path, chunksize=chunksize, low_memory=False):
        chunk.columns = [str(col).strip().lower() for col in chunk.columns]
        if "label" not in chunk.columns:
            raise ValueError("UNSW-NB15 training CSV must contain a 'label' column.")

        labels = pd.to_numeric(chunk["label"], errors="coerce")
        benign_mask = labels == 0
        if benign_mask.any():
            benign_chunks.append(map_unsw_chunk_to_flow_features(chunk.loc[benign_mask]))

    if not benign_chunks:
        raise ValueError("No benign rows (label == 0) found in UNSW-NB15 training CSV.")

    return pd.concat(benign_chunks, ignore_index=True)


def load_unsw_testing_data(test_csv, chunksize=25000):
    """Load and map the complete UNSW-NB15 testing CSV in chunks."""
    test_path = Path(test_csv)
    if not test_path.exists():
        raise FileNotFoundError(f"UNSW-NB15 testing CSV not found: {test_path}")

    feature_chunks = []
    label_chunks = []
    attack_cat_chunks = []

    for chunk in pd.read_csv(test_path, chunksize=chunksize, low_memory=False):
        chunk.columns = [str(col).strip().lower() for col in chunk.columns]
        if "label" not in chunk.columns:
            raise ValueError("UNSW-NB15 testing CSV must contain a 'label' column.")

        labels = pd.to_numeric(chunk["label"], errors="coerce")
        valid_mask = labels.isin([0, 1])
        if not valid_mask.any():
            continue

        valid_chunk = chunk.loc[valid_mask]
        valid_labels = labels.loc[valid_mask].astype(int)

        feature_chunks.append(map_unsw_chunk_to_flow_features(valid_chunk))
        label_chunks.append(valid_labels)

        if "attack_cat" in valid_chunk.columns:
            cats = (
                valid_chunk["attack_cat"]
                .fillna("Unknown")
                .astype(str)
                .str.strip()
                .replace({"": "Unknown", "-": "Unknown"})
            )
            cats = cats.where(valid_labels == 1, "Normal")
        else:
            cats = pd.Series(
                np.where(valid_labels == 0, "Normal", "Attack"),
                index=valid_chunk.index,
            )
        attack_cat_chunks.append(cats)

    if not feature_chunks:
        raise ValueError("No valid test rows found in UNSW-NB15 testing CSV.")

    X_test = pd.concat(feature_chunks, ignore_index=True)
    y_test = pd.concat(label_chunks, ignore_index=True).to_numpy(dtype=int)
    attack_cats = pd.concat(attack_cat_chunks, ignore_index=True)
    return X_test, y_test, attack_cats


def train_and_evaluate_unsw(
    train_csv=DEFAULT_TRAIN_CSV,
    test_csv=DEFAULT_TEST_CSV,
    model_path=DEFAULT_UNSW_MODEL_PATH,
    chunksize=25000,
    contamination=0.05,
    n_estimators=200,
    random_state=42,
):
    """Train IsolationForest on benign UNSW-NB15 rows, evaluate on full test set, and save."""
    X_train_benign = load_unsw_training_benign_features(train_csv, chunksize=chunksize)
    X_test, y_test, attack_cats = load_unsw_testing_data(test_csv, chunksize=chunksize)

    pipeline = build_pipeline(
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_state,
    )
    pipeline.fit(X_train_benign[FLOW_FEATURES])

    train_scores = pipeline.decision_function(X_train_benign[FLOW_FEATURES])
    score_scale = float(max(np.std(train_scores), 0.05))

    raw_preds = pipeline.predict(X_test[FLOW_FEATURES])
    y_pred = np.where(raw_preds == -1, 1, 0)

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))

    attack_cat_counts = {
        str(k): int(v) for k, v in attack_cats.value_counts().to_dict().items()
    }
    attack_categories_only = sorted(
        cat for cat in attack_cat_counts if cat.lower() != "normal"
    )

    metrics = {
        "benign_training_rows": int(len(X_train_benign)),
        "test_rows": int(len(X_test)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": cm.tolist(),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "attack_categories": attack_categories_only,
        "attack_category_counts": attack_cat_counts,
    }

    output_path = Path(model_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "dataset": "UNSW-NB15",
        "pipeline": pipeline,
        "features": list(FLOW_FEATURES),
        "score_scale": score_scale,
        "contamination": contamination,
        "n_estimators": n_estimators,
        "random_state": random_state,
        "evaluation_metrics": metrics,
    }
    joblib.dump(bundle, output_path)

    return {
        "model_path": output_path,
        "metrics": metrics,
        "bundle": bundle,
    }


def print_unsw_report(model_path, metrics):
    """Print clear UNSW-NB15 training and evaluation metrics."""
    print(f"Saved UNSW-NB15 IsolationForest model to: {model_path}")
    print("\n=== UNSW-NB15 Evaluation Summary ===")
    print(f"Benign Training Rows : {metrics['benign_training_rows']}")
    print(f"Test Rows            : {metrics['test_rows']}")
    print(f"Precision            : {metrics['precision']:.4f}")
    print(f"Recall               : {metrics['recall']:.4f}")
    print(f"F1-Score             : {metrics['f1_score']:.4f}")
    print("\nConfusion Matrix (rows = Actual, cols = Predicted):")
    print("                  Pred Normal (0)   Pred Attack (1)")
    print(f"Actual Normal (0)     {metrics['tn']:>8d}          {metrics['fp']:>8d}")
    print(f"Actual Attack (1)     {metrics['fn']:>8d}          {metrics['tp']:>8d}")
    print("\nTest Set Attack Categories:")
    for cat, count in metrics["attack_category_counts"].items():
        print(f"  - {cat}: {count}")


def main():
    """CLI entry point for UNSW-NB15 IsolationForest training."""
    parser = argparse.ArgumentParser(description="Train IsolationForest on UNSW-NB15 benign flows.")
    parser.add_argument("--train-csv", type=Path, default=DEFAULT_TRAIN_CSV)
    parser.add_argument("--test-csv", type=Path, default=DEFAULT_TEST_CSV)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_UNSW_MODEL_PATH)
    parser.add_argument("--chunksize", type=int, default=25000)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    result = train_and_evaluate_unsw(
        train_csv=args.train_csv,
        test_csv=args.test_csv,
        model_path=args.model_path,
        chunksize=args.chunksize,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=args.seed,
    )
    print_unsw_report(result["model_path"], result["metrics"])


if __name__ == "__main__":
    main()

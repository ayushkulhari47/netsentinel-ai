"""Generate synthetic benign and anomalous network-flow datasets for NetSentinel AI."""

import argparse
from pathlib import Path
import sys
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.ml.feature_schema import FLOW_FEATURES, validate_flow_dataframe  # noqa: E402

DEFAULT_DATA_DIR = PROJECT_ROOT / "data"


def _finalize_flows(rows):
    """Build a DataFrame with derived rate metrics and validate against FLOW_FEATURES."""
    df = pd.DataFrame(rows)
    df["flow_packets"] = df["forward_packets"] + df["backward_packets"]
    df["flow_bytes"] = np.round(df["flow_packets"] * df["average_packet_size"], 2)
    safe_duration = np.maximum(df["duration"], 0.001)
    df["packet_rate"] = np.round(df["flow_packets"] / safe_duration, 4)
    df["byte_rate"] = np.round(df["flow_bytes"] / safe_duration, 4)
    return validate_flow_dataframe(df[FLOW_FEATURES])


def generate_benign_flows(n_samples=1200, random_state=42):
    """Generate realistic synthetic benign network flows (HTTPS, DNS, SSH)."""
    rng = np.random.default_rng(random_state)
    rows = []

    for _ in range(n_samples):
        profile = rng.choice(["https", "dns", "ssh"], p=[0.6, 0.25, 0.15])

        if profile == "https":
            duration = float(np.round(rng.uniform(0.2, 15.0), 4))
            protocol = "TCP"
            source_port = int(rng.integers(49152, 65535))
            destination_port = int(rng.choice([443, 80, 8080], p=[0.75, 0.2, 0.05]))
            forward_packets = int(rng.integers(6, 45))
            backward_packets = int(rng.integers(6, 60))
            avg_size = float(np.round(rng.uniform(250.0, 1150.0), 2))
        elif profile == "dns":
            duration = float(np.round(rng.uniform(0.02, 0.35), 4))
            protocol = "UDP"
            source_port = int(rng.integers(49152, 65535))
            destination_port = 53
            forward_packets = int(rng.integers(1, 4))
            backward_packets = int(rng.integers(1, 4))
            avg_size = float(np.round(rng.uniform(64.0, 180.0), 2))
        else:
            duration = float(np.round(rng.uniform(2.0, 40.0), 4))
            protocol = "TCP"
            source_port = int(rng.integers(49152, 65535))
            destination_port = 22
            forward_packets = int(rng.integers(10, 75))
            backward_packets = int(rng.integers(10, 75))
            avg_size = float(np.round(rng.uniform(90.0, 400.0), 2))

        rows.append(
            {
                "duration": duration,
                "protocol": protocol,
                "source_port": source_port,
                "destination_port": destination_port,
                "forward_packets": forward_packets,
                "backward_packets": backward_packets,
                "average_packet_size": avg_size,
            }
        )

    return _finalize_flows(rows)


def generate_anomalous_flows(n_samples=300, random_state=99):
    """Generate synthetic anomalous network flows for evaluation."""
    rng = np.random.default_rng(random_state)
    rows = []

    for _ in range(n_samples):
        attack = rng.choice(["syn_flood", "port_scan", "exfiltration", "icmp_flood"])

        if attack == "syn_flood":
            duration = float(np.round(rng.uniform(0.05, 1.0), 4))
            protocol = "TCP"
            source_port = int(rng.integers(1024, 65535))
            destination_port = int(rng.choice([80, 443]))
            forward_packets = int(rng.integers(600, 3500))
            backward_packets = int(rng.integers(0, 4))
            avg_size = float(np.round(rng.uniform(54.0, 74.0), 2))
        elif attack == "port_scan":
            duration = float(np.round(rng.uniform(0.002, 0.015), 4))
            protocol = "TCP"
            source_port = int(rng.integers(30000, 65535))
            destination_port = int(rng.integers(1, 1024))
            forward_packets = int(rng.integers(15, 60))
            backward_packets = 0
            avg_size = float(np.round(rng.uniform(44.0, 60.0), 2))
        elif attack == "exfiltration":
            duration = float(np.round(rng.uniform(0.5, 4.0), 4))
            protocol = "TCP"
            source_port = int(rng.integers(49152, 65535))
            destination_port = int(rng.choice([4444, 8443, 9001]))
            forward_packets = int(rng.integers(400, 1800))
            backward_packets = int(rng.integers(2, 20))
            avg_size = float(np.round(rng.uniform(1200.0, 1480.0), 2))
        else:
            duration = float(np.round(rng.uniform(0.1, 1.5), 4))
            protocol = "ICMP"
            source_port = 0
            destination_port = 0
            forward_packets = int(rng.integers(400, 2200))
            backward_packets = int(rng.integers(0, 5))
            avg_size = float(np.round(rng.uniform(64.0, 128.0), 2))

        rows.append(
            {
                "duration": duration,
                "protocol": protocol,
                "source_port": source_port,
                "destination_port": destination_port,
                "forward_packets": forward_packets,
                "backward_packets": backward_packets,
                "average_packet_size": avg_size,
            }
        )

    return _finalize_flows(rows)


def generate_datasets(
    output_dir=DEFAULT_DATA_DIR,
    train_samples=1200,
    eval_benign_samples=300,
    eval_anomaly_samples=300,
    random_state=42,
):
    """Generate and save benign training and benign/anomalous evaluation CSVs."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    train_benign_df = generate_benign_flows(n_samples=train_samples, random_state=random_state)
    eval_benign_df = generate_benign_flows(
        n_samples=eval_benign_samples, random_state=random_state + 100
    )
    eval_anomalous_df = generate_anomalous_flows(
        n_samples=eval_anomaly_samples, random_state=random_state + 200
    )

    train_path = output_path / "benign_train.csv"
    eval_benign_path = output_path / "benign_eval.csv"
    eval_anomalous_path = output_path / "anomalous_eval.csv"

    train_benign_df.to_csv(train_path, index=False)
    eval_benign_df.to_csv(eval_benign_path, index=False)
    eval_anomalous_df.to_csv(eval_anomalous_path, index=False)

    return {
        "train_benign_path": train_path,
        "eval_benign_path": eval_benign_path,
        "eval_anomalous_path": eval_anomalous_path,
        "train_benign_df": train_benign_df,
        "eval_benign_df": eval_benign_df,
        "eval_anomalous_df": eval_anomalous_df,
    }


def main():
    """CLI entry point for generating synthetic demo datasets."""
    parser = argparse.ArgumentParser(description="Generate synthetic network-flow datasets.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--train-samples", type=int, default=1200)
    parser.add_argument("--eval-benign-samples", type=int, default=300)
    parser.add_argument("--eval-anomaly-samples", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    result = generate_datasets(
        output_dir=args.output_dir,
        train_samples=args.train_samples,
        eval_benign_samples=args.eval_benign_samples,
        eval_anomaly_samples=args.eval_anomaly_samples,
        random_state=args.seed,
    )
    print(f"Saved benign training dataset ({len(result['train_benign_df'])} rows): {result['train_benign_path']}")
    print(f"Saved benign evaluation dataset ({len(result['eval_benign_df'])} rows): {result['eval_benign_path']}")
    print(f"Saved anomalous evaluation dataset ({len(result['eval_anomalous_df'])} rows): {result['eval_anomalous_path']}")


if __name__ == "__main__":
    main()

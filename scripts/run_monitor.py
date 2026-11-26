"""Controlled end-to-end monitoring CLI connecting capture, ML detection, and SQLite."""

import argparse
from pathlib import Path
import signal
import sys
import threading

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app  # noqa: E402
from app.services.monitoring_service import MonitoringService  # noqa: E402


def build_parser():
    """Create the CLI argument parser for safe demo or authorized live monitoring."""
    parser = argparse.ArgumentParser(
        description=(
            "NetSentinel AI controlled monitoring runner. "
            "Requires --demo (synthetic metadata) or explicit --live (authorized interface)."
        )
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--demo",
        action="store_true",
        help="Process safe synthetic normal and suspicious metadata without sending/capturing live traffic.",
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        help="Explicitly authorize live metadata capture on a local interface you own/control.",
    )
    parser.add_argument("--interface", type=str, default=None, help="Network interface name.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum packets to capture/process.")
    parser.add_argument("--timeout", type=float, default=None, help="Capture timeout in seconds.")
    parser.add_argument("--filter", type=str, default=None, dest="bpf_filter", help="Optional BPF filter.")
    return parser


def generate_demo_packet_stream():
    """Return synthetic metadata records producing both normal and suspicious flows.

    No real network packets, scans, or exploits are generated or transmitted.
    """
    packets = []

    # 1. Normal HTTPS flow (bidirectional, low packet rate -> no alert)
    packets.extend(
        [
            {
                "timestamp": 1000.0,
                "source_ip": "192.168.1.50",
                "destination_ip": "93.184.216.34",
                "source_port": 54120,
                "destination_port": 443,
                "protocol": "TCP",
                "packet_length": 74,
                "tcp_flags": "S",
            },
            {
                "timestamp": 1000.5,
                "source_ip": "93.184.216.34",
                "destination_ip": "192.168.1.50",
                "source_port": 443,
                "destination_port": 54120,
                "protocol": "TCP",
                "packet_length": 74,
                "tcp_flags": "SA",
            },
            {
                "timestamp": 1001.2,
                "source_ip": "192.168.1.50",
                "destination_ip": "93.184.216.34",
                "source_port": 54120,
                "destination_port": 443,
                "protocol": "TCP",
                "packet_length": 512,
                "tcp_flags": "PA",
            },
            {
                "timestamp": 1002.0,
                "source_ip": "93.184.216.34",
                "destination_ip": "192.168.1.50",
                "source_port": 443,
                "destination_port": 54120,
                "protocol": "TCP",
                "packet_length": 1100,
                "tcp_flags": "PA",
            },
        ]
    )

    # 2. Normal DNS lookup flow (bidirectional, low rate -> no alert)
    packets.extend(
        [
            {
                "timestamp": 1050.0,
                "source_ip": "192.168.1.50",
                "destination_ip": "1.1.1.1",
                "source_port": 55200,
                "destination_port": 53,
                "protocol": "UDP",
                "packet_length": 68,
                "tcp_flags": None,
            },
            {
                "timestamp": 1050.04,
                "source_ip": "1.1.1.1",
                "destination_ip": "192.168.1.50",
                "source_port": 53,
                "destination_port": 55200,
                "protocol": "UDP",
                "packet_length": 124,
                "tcp_flags": None,
            },
        ]
    )

    # 3. Suspicious high-rate outbound metadata flow on port 4444 -> persisted alert
    for idx in range(25):
        packets.append(
            {
                "timestamp": 1100.0 + idx * 0.001,
                "source_ip": "198.51.100.77",
                "destination_ip": "10.0.0.15",
                "source_port": 40123,
                "destination_port": 4444,
                "protocol": "TCP",
                "packet_length": 1400,
                "tcp_flags": "S",
            }
        )

    # 4. Suspicious UDP-to-Telnet protocol/port combination -> persisted alert
    packets.extend(
        [
            {
                "timestamp": 1150.0,
                "source_ip": "198.51.100.88",
                "destination_ip": "10.0.0.12",
                "source_port": 50000,
                "destination_port": 23,
                "protocol": "UDP",
                "packet_length": 120,
                "tcp_flags": None,
            },
            {
                "timestamp": 1150.5,
                "source_ip": "198.51.100.88",
                "destination_ip": "10.0.0.12",
                "source_port": 50000,
                "destination_port": 23,
                "protocol": "UDP",
                "packet_length": 120,
                "tcp_flags": None,
            },
        ]
    )

    return packets


def run_demo_monitoring(app=None, monitoring_service=None, limit=None):
    """Run the full monitoring pipeline on synthetic normal and suspicious metadata."""
    flask_app = app if app is not None else create_app()
    packets = generate_demo_packet_stream()
    if limit is not None:
        if limit <= 0:
            raise ValueError("--limit must be a positive integer.")
        packets = packets[:limit]

    with flask_app.app_context():
        service = monitoring_service if monitoring_service is not None else MonitoringService(
            threat_intel_service=flask_app.extensions.get("threat_intel_service"),
            llm_explainer=flask_app.extensions.get("llm_explainer"),
        )
        return service.process_packets(packets, flush=True)


def main(argv=None, app=None, monitoring_service=None, sniff_fn=None):
    """CLI entry point requiring --demo or explicit --live authorization."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.demo and not args.live:
        print(
            "Refusing to run live monitoring without explicit --live flag. "
            "Use --demo for safe synthetic metadata or pass --live only on an "
            "interface you own or are authorized to monitor.",
            file=sys.stderr,
        )
        return 2

    if args.demo:
        try:
            result = run_demo_monitoring(
                app=app,
                monitoring_service=monitoring_service,
                limit=args.limit,
            )
        except ValueError as exc:
            print(f"Invalid argument: {exc}", file=sys.stderr)
            return 2

        print(
            f"[DEMO] Processed {result['packets_processed']} synthetic packets across "
            f"{result['flows_analyzed']} flow(s); created {result['alerts_created']} alert(s)."
        )
        return 0

    flask_app = app if app is not None else create_app()
    with flask_app.app_context():
        service = monitoring_service if monitoring_service is not None else MonitoringService(
            threat_intel_service=flask_app.extensions.get("threat_intel_service"),
            llm_explainer=flask_app.extensions.get("llm_explainer"),
        )

        is_main_thread = threading.current_thread() is threading.main_thread()
        previous_handler = signal.getsignal(signal.SIGINT) if is_main_thread else None

        def _handle_sigint(_signum, _frame):
            service.request_stop()
            raise KeyboardInterrupt

        if is_main_thread:
            signal.signal(signal.SIGINT, _handle_sigint)
        try:
            result = service.run_live(
                live=True,
                interface=args.interface,
                bpf_filter=args.bpf_filter,
                packet_limit=args.limit,
                timeout=args.timeout,
                sniff_fn=sniff_fn,
            )
        except ValueError as exc:
            print(f"Invalid argument: {exc}", file=sys.stderr)
            return 2
        finally:
            if is_main_thread and previous_handler is not None:
                signal.signal(signal.SIGINT, previous_handler)

    status_label = "interrupted cleanly" if result["interrupted"] else "completed"
    print(
        f"[LIVE] Monitoring {status_label}: seen={result['packets_seen']}, "
        f"processed={result['packets_processed']}, ignored={result['packets_ignored']}, "
        f"flows_analyzed={result['flows_analyzed']}, alerts_created={result['alerts_created']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

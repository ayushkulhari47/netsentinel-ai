"""Controlled CLI runner for NetSentinel AI packet metadata capture."""

import argparse
from pathlib import Path
import signal
import sys
import threading

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.flow_aggregator import FlowAggregator  # noqa: E402
from app.services.packet_capture import PacketCaptureService  # noqa: E402


def build_parser():
    """Create the CLI argument parser for safe demo or authorized live capture."""
    parser = argparse.ArgumentParser(
        description=(
            "NetSentinel AI controlled packet capture CLI. "
            "Captures metadata only (no payloads) and requires explicit --live or --demo."
        )
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--demo",
        action="store_true",
        help="Run using safe synthetic benign metadata without touching a network interface.",
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        help="Explicitly authorize live capture on a local interface you own/control.",
    )
    parser.add_argument("--interface", type=str, default=None, help="Network interface name.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum packets to capture.")
    parser.add_argument("--timeout", type=float, default=None, help="Capture timeout in seconds.")
    parser.add_argument("--filter", type=str, default=None, dest="bpf_filter", help="Optional BPF filter.")
    return parser


def generate_safe_demo_packets():
    """Return benign synthetic packet metadata records (no live traffic, no attacks)."""
    return [
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
            "timestamp": 1000.05,
            "source_ip": "93.184.216.34",
            "destination_ip": "192.168.1.50",
            "source_port": 443,
            "destination_port": 54120,
            "protocol": "TCP",
            "packet_length": 74,
            "tcp_flags": "SA",
        },
        {
            "timestamp": 1000.12,
            "source_ip": "192.168.1.50",
            "destination_ip": "93.184.216.34",
            "source_port": 54120,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_length": 512,
            "tcp_flags": "PA",
        },
        {
            "timestamp": 1001.0,
            "source_ip": "192.168.1.50",
            "destination_ip": "1.1.1.1",
            "source_port": 55200,
            "destination_port": 53,
            "protocol": "UDP",
            "packet_length": 68,
            "tcp_flags": None,
        },
        {
            "timestamp": 1001.03,
            "source_ip": "1.1.1.1",
            "destination_ip": "192.168.1.50",
            "source_port": 53,
            "destination_port": 55200,
            "protocol": "UDP",
            "packet_length": 124,
            "tcp_flags": None,
        },
    ]


def run_demo_mode(limit=None):
    """Aggregate safe synthetic packet metadata into network flows without sniffing."""
    aggregator = FlowAggregator(inactivity_timeout=30.0)
    packets = generate_safe_demo_packets()
    if limit is not None:
        if limit <= 0:
            raise ValueError("--limit must be a positive integer.")
        packets = packets[:limit]

    for pkt in packets:
        aggregator.add_packet(pkt)

    flows = aggregator.flush_all()
    return {
        "mode": "demo",
        "packets_seen": len(packets),
        "packets_processed": len(packets),
        "packets_ignored": 0,
        "flows": flows,
        "interrupted": False,
    }


def main(argv=None, capture_service_cls=PacketCaptureService):
    """CLI entry point enforcing --live authorization for real interface capture."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.demo and not args.live:
        print(
            "Refusing to run live packet capture without explicit --live flag. "
            "Use --demo for safe synthetic metadata or pass --live only on an "
            "interface you own or are authorized to monitor.",
            file=sys.stderr,
        )
        return 2

    if args.demo:
        try:
            result = run_demo_mode(limit=args.limit)
        except ValueError as exc:
            print(f"Invalid argument: {exc}", file=sys.stderr)
            return 2
        print(
            f"[DEMO] Processed {result['packets_processed']} synthetic packets "
            f"into {len(result['flows'])} flow(s)."
        )
        return 0

    try:
        service = capture_service_cls(
            interface=args.interface,
            bpf_filter=args.bpf_filter,
            packet_limit=args.limit,
            timeout=args.timeout,
        )
    except ValueError as exc:
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 2

    is_main_thread = threading.current_thread() is threading.main_thread()
    previous_handler = signal.getsignal(signal.SIGINT) if is_main_thread else None

    def _handle_sigint(_signum, _frame):
        service.request_stop()
        raise KeyboardInterrupt

    if is_main_thread:
        signal.signal(signal.SIGINT, _handle_sigint)
    try:
        result = service.capture_live(live=True)
    finally:
        if is_main_thread and previous_handler is not None:
            signal.signal(signal.SIGINT, previous_handler)

    status_label = "interrupted cleanly" if result["interrupted"] else "completed"
    print(
        f"[LIVE] Capture {status_label}: seen={result['packets_seen']}, "
        f"processed={result['packets_processed']}, ignored={result['packets_ignored']}, "
        f"flows={len(result['flows'])}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

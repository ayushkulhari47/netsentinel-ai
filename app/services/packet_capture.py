"""Controlled Scapy metadata-only packet capture service for NetSentinel AI."""

import math
import numbers
import threading
import time

from app.services.flow_aggregator import FlowAggregator

# Standard IPv6 Next Header value for ICMPv6
_IPV6_NEXT_HEADER_ICMPV6 = 58


def _safe_timestamp(packet):
    """Extract a valid finite packet timestamp or fall back to current epoch seconds."""
    raw_time = getattr(packet, "time", None)
    if (
        isinstance(raw_time, numbers.Real)
        and not isinstance(raw_time, bool)
        and math.isfinite(float(raw_time))
        and float(raw_time) >= 0.0
    ):
        return float(raw_time)
    return time.time()


def _safe_packet_length(packet):
    """Extract packet length in bytes without inspecting packet payload contents."""
    wirelen = getattr(packet, "wirelen", None)
    if isinstance(wirelen, numbers.Integral) and not isinstance(wirelen, bool) and int(wirelen) >= 0:
        return int(wirelen)
    try:
        length = len(packet)
        return max(0, int(length))
    except TypeError:
        return 0


def _get_layer(packet, layer_name):
    """Safely retrieve a Scapy-style layer by name if present on packet."""
    has_layer = getattr(packet, "haslayer", None)
    get_layer = getattr(packet, "getlayer", None)
    if callable(has_layer) and callable(get_layer) and has_layer(layer_name):
        return get_layer(layer_name)
    return None


def extract_packet_metadata(packet):
    """Extract metadata-only fields from an IPv4/IPv6 TCP/UDP/ICMP packet.

    Returns a dictionary containing:
      - timestamp
      - source_ip
      - destination_ip
      - source_port
      - destination_port
      - protocol
      - packet_length
      - tcp_flags

    Never reads or stores packet payload bytes. Returns None for unsupported packets.
    """
    if packet is None:
        return None

    ip_layer = _get_layer(packet, "IP")
    is_ipv6 = False
    if ip_layer is None:
        ip_layer = _get_layer(packet, "IPv6")
        is_ipv6 = ip_layer is not None

    if ip_layer is None:
        return None

    source_ip = getattr(ip_layer, "src", None)
    destination_ip = getattr(ip_layer, "dst", None)
    if not isinstance(source_ip, str) or not isinstance(destination_ip, str):
        return None

    tcp_layer = _get_layer(packet, "TCP")
    udp_layer = _get_layer(packet, "UDP")
    icmp_layer = _get_layer(packet, "ICMP")

    if tcp_layer is not None:
        protocol = "TCP"
        source_port = getattr(tcp_layer, "sport", None)
        destination_port = getattr(tcp_layer, "dport", None)
        raw_flags = getattr(tcp_layer, "flags", None)
        tcp_flags = str(raw_flags) if raw_flags not in (None, "") else None
    elif udp_layer is not None:
        protocol = "UDP"
        source_port = getattr(udp_layer, "sport", None)
        destination_port = getattr(udp_layer, "dport", None)
        tcp_flags = None
    elif icmp_layer is not None or (
        is_ipv6 and getattr(ip_layer, "nh", None) == _IPV6_NEXT_HEADER_ICMPV6
    ):
        protocol = "ICMP"
        source_port = 0
        destination_port = 0
        tcp_flags = None
    else:
        return None

    if source_port is None or destination_port is None:
        return None

    try:
        src_port_int = int(source_port)
        dst_port_int = int(destination_port)
    except (TypeError, ValueError):
        return None

    if not (0 <= src_port_int <= 65535 and 0 <= dst_port_int <= 65535):
        return None

    return {
        "timestamp": _safe_timestamp(packet),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": src_port_int,
        "destination_port": dst_port_int,
        "protocol": protocol,
        "packet_length": _safe_packet_length(packet),
        "tcp_flags": tcp_flags,
    }


class PacketCaptureService:
    """Controlled Scapy capture wrapper that forwards metadata to FlowAggregator."""

    def __init__(
        self,
        flow_aggregator=None,
        interface=None,
        bpf_filter=None,
        packet_limit=None,
        timeout=None,
        sniff_fn=None,
    ):
        """Configure capture parameters without starting any network capture."""
        if interface is not None and (not isinstance(interface, str) or not interface.strip()):
            raise ValueError("interface must be a non-empty string when provided.")
        if bpf_filter is not None and not isinstance(bpf_filter, str):
            raise ValueError("bpf_filter must be a string when provided.")
        if packet_limit is not None:
            if isinstance(packet_limit, bool) or not isinstance(packet_limit, int) or packet_limit <= 0:
                raise ValueError("packet_limit must be a positive integer.")
        if timeout is not None:
            if (
                isinstance(timeout, bool)
                or not isinstance(timeout, numbers.Real)
                or not math.isfinite(float(timeout))
                or float(timeout) <= 0.0
            ):
                raise ValueError("timeout must be a positive number.")

        self.flow_aggregator = flow_aggregator if flow_aggregator is not None else FlowAggregator()
        self.interface = interface.strip() if interface is not None else None
        self.bpf_filter = bpf_filter.strip() if bpf_filter is not None and bpf_filter.strip() else None
        self.packet_limit = packet_limit
        self.timeout = float(timeout) if timeout is not None else None
        self._sniff_fn = sniff_fn

        self._stop_event = threading.Event()
        self.packets_seen = 0
        self.packets_processed = 0
        self.packets_ignored = 0

    def request_stop(self):
        """Signal the capture loop to stop gracefully."""
        self._stop_event.set()

    def handle_packet(self, packet):
        """Extract metadata from one packet and forward it to FlowAggregator."""
        self.packets_seen += 1
        metadata = extract_packet_metadata(packet)
        if metadata is None:
            self.packets_ignored += 1
            return None

        self.flow_aggregator.add_packet(metadata)
        self.packets_processed += 1
        return metadata

    def _resolve_sniff_fn(self):
        """Lazily import Scapy's sniff function only when live capture is invoked."""
        if self._sniff_fn is not None:
            return self._sniff_fn
        from scapy.all import sniff  # pylint: disable=import-outside-toplevel

        return sniff

    def capture_live(self, live=False):
        """Capture packet metadata using Scapy (store=False). Requires live=True."""
        if live is not True:
            raise PermissionError(
                "Refusing to start live packet capture without explicit live=True authorization."
            )

        self._stop_event.clear()
        sniff_fn = self._resolve_sniff_fn()

        sniff_kwargs = {
            "store": False,
            "prn": self.handle_packet,
            "stop_filter": lambda _pkt: self._stop_event.is_set(),
        }
        if self.interface is not None:
            sniff_kwargs["iface"] = self.interface
        if self.bpf_filter is not None:
            sniff_kwargs["filter"] = self.bpf_filter
        if self.packet_limit is not None:
            sniff_kwargs["count"] = self.packet_limit
        if self.timeout is not None:
            sniff_kwargs["timeout"] = self.timeout

        interrupted = False
        try:
            sniff_fn(**sniff_kwargs)
        except KeyboardInterrupt:
            interrupted = True
            self.request_stop()
        finally:
            flows = self.flow_aggregator.flush_all()

        return {
            "mode": "live",
            "packets_seen": self.packets_seen,
            "packets_processed": self.packets_processed,
            "packets_ignored": self.packets_ignored,
            "flows": flows,
            "interrupted": interrupted,
        }

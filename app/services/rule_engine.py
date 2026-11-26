"""Explainable heuristic rule engine for NetSentinel AI flow analysis."""

from app.ml.feature_schema import validate_flow_record

SUSPICIOUS_PORTS = {
    23: "Telnet",
    445: "SMB",
    1337: "commonly abused non-standard port 1337",
    4444: "commonly abused reverse-shell port 4444",
    5555: "commonly abused port 5555",
    6667: "IRC",
    9001: "commonly abused port 9001",
    31337: "commonly abused port 31337",
}

TCP_ONLY_ADMIN_PORTS = {22, 23, 445, 3389}
STANDARD_WEB_PORTS = {80, 443, 8080, 8443}


def normalize_tcp_flag_list(flow):
    """Extract normalized uppercase TCP flag strings from a flow record."""
    raw = flow.get("tcp_flags") if isinstance(flow, dict) else None
    if isinstance(raw, (list, tuple, set)):
        return [str(flag).strip().upper() for flag in raw if str(flag).strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip().upper()]
    return []


def is_established_bidirectional_tcp(flow, tcp_flags=None):
    """Return True if flow represents established bidirectional TCP with ACK/PA flags."""
    flags = tcp_flags if tcp_flags is not None else normalize_tcp_flag_list(flow)
    protocol = str(flow.get("protocol", "")).strip().upper()
    fwd = float(flow.get("forward_packets", 0) or 0)
    bwd = float(flow.get("backward_packets", 0) or 0)
    has_ack = any("A" in flag for flag in flags)
    return protocol == "TCP" and fwd > 0 and bwd > 0 and has_ack


def is_likely_normal_web_traffic(flow, tcp_flags=None):
    """Return True for established bidirectional TCP on standard HTTP/HTTPS web ports."""
    if not is_established_bidirectional_tcp(flow, tcp_flags=tcp_flags):
        return False
    src_port = int(flow.get("source_port", 0) or 0)
    dst_port = int(flow.get("destination_port", 0) or 0)
    return src_port in STANDARD_WEB_PORTS or dst_port in STANDARD_WEB_PORTS


class RuleEngine:
    """Evaluates normalized network flows against transparent security rules."""

    def __init__(
        self,
        high_packet_rate=500.0,
        extreme_packet_rate=1500.0,
        high_byte_rate=250_000.0,
        extreme_byte_rate=1_000_000.0,
        large_flow_bytes=500_000.0,
        large_flow_packets=1000,
    ):
        """Initialize configurable thresholds for heuristic flow rules."""
        self.high_packet_rate = float(high_packet_rate)
        self.extreme_packet_rate = float(extreme_packet_rate)
        self.high_byte_rate = float(high_byte_rate)
        self.extreme_byte_rate = float(extreme_byte_rate)
        self.large_flow_bytes = float(large_flow_bytes)
        self.large_flow_packets = int(large_flow_packets)

    def evaluate(self, flow):
        """Evaluate a flow dictionary and return rule score, matches, and evidence."""
        cleaned = validate_flow_record(flow)
        tcp_flags = normalize_tcp_flag_list(flow)
        established_tcp = is_established_bidirectional_tcp(cleaned, tcp_flags=tcp_flags)
        normal_web_flow = is_likely_normal_web_traffic(cleaned, tcp_flags=tcp_flags)

        matched_rules = []
        evidence = []
        attack_hints = []
        context_notes = []

        packet_rate = cleaned["packet_rate"]
        byte_rate = cleaned["byte_rate"]
        flow_bytes = cleaned["flow_bytes"]
        flow_packets = cleaned["flow_packets"]
        backward_packets = cleaned["backward_packets"]
        protocol = cleaned["protocol"]
        src_port = cleaned["source_port"]
        dst_port = cleaned["destination_port"]

        if established_tcp:
            context_notes.append(
                "Established bidirectional TCP traffic with ACK/PA flags observed; "
                "rate-based flood heuristics applied cautiously."
            )

        # 1. Unusually high packet rate (suppressed for normal short HTTPS/HTTP responses)
        if packet_rate >= self.high_packet_rate:
            if (
                normal_web_flow
                and flow_packets < self.large_flow_packets
                and byte_rate < self.extreme_byte_rate
            ):
                context_notes.append(
                    f"Packet rate ({packet_rate:.1f} pkt/s) on established web port "
                    f"({src_port}->{dst_port}) was not classified as a flood."
                )
            else:
                is_extreme = packet_rate >= self.extreme_packet_rate
                if established_tcp:
                    points = 25.0
                    hint = "Possible Elevated Packet Rate (Established TCP)"
                else:
                    points = 30.0 if is_extreme else 25.0
                    syn_only = "S" in tcp_flags and not any("A" in f for f in tcp_flags) and backward_packets == 0
                    hint = "Possible SYN/Packet Flood" if syn_only else "Possible High-Rate Packet Flood"
                detail = (
                    f"Suspiciously high packet rate observed ({packet_rate:.1f} pkt/s, "
                    f"threshold {self.high_packet_rate:.0f} pkt/s)"
                )
                if not established_tcp and "S" in tcp_flags and not any("A" in f for f in tcp_flags) and backward_packets == 0:
                    detail += " with unanswered SYN flags"
                detail += "."
                matched_rules.append(
                    {
                        "rule_id": "high_packet_rate",
                        "title": "Unusually High Packet Rate",
                        "points": points,
                        "attack_hint": hint,
                        "detail": detail,
                    }
                )
                evidence.append(detail)
                attack_hints.append(hint)

        # 2. Unusually high byte rate
        if byte_rate >= self.high_byte_rate:
            if (
                normal_web_flow
                and flow_bytes < self.large_flow_bytes
                and flow_packets < self.large_flow_packets
            ):
                context_notes.append(
                    f"Short web transfer byte rate ({byte_rate:.1f} B/s) remained below "
                    f"large-flow volume threshold ({self.large_flow_bytes:.0f} bytes)."
                )
            else:
                is_extreme = byte_rate >= self.extreme_byte_rate
                points = 25.0 if established_tcp else (35.0 if is_extreme else 25.0)
                hint = "Possible High-Throughput Exfiltration or Flood"
                detail = (
                    f"Suspiciously high byte rate observed ({byte_rate:.1f} B/s, "
                    f"threshold {self.high_byte_rate:.0f} B/s)."
                )
                matched_rules.append(
                    {
                        "rule_id": "high_byte_rate",
                        "title": "Unusually High Byte Rate",
                        "points": points,
                        "attack_hint": hint,
                        "detail": detail,
                    }
                )
                evidence.append(detail)
                attack_hints.append(hint)

        # 3. Unusually large flow size
        if flow_bytes >= self.large_flow_bytes or flow_packets >= self.large_flow_packets:
            points = 25.0 if (flow_bytes >= self.large_flow_bytes and flow_packets >= self.large_flow_packets) else 20.0
            hint = "Possible Bulk Transfer or Data Exfiltration"
            detail = (
                f"Unusually large flow volume detected ({flow_bytes:.0f} bytes across "
                f"{int(flow_packets)} packets)."
            )
            matched_rules.append(
                {
                    "rule_id": "large_flow_size",
                    "title": "Unusually Large Flow Size",
                    "points": points,
                    "attack_hint": hint,
                    "detail": detail,
                }
            )
            evidence.append(detail)
            attack_hints.append(hint)

        # 4. Suspicious protocol or port combinations
        port_reasons = []
        if protocol == "ICMP" and (src_port != 0 or dst_port != 0):
            port_reasons.append(
                f"ICMP flow carries unexpected non-zero ports ({src_port} -> {dst_port})"
            )
        if protocol == "UDP" and dst_port in TCP_ONLY_ADMIN_PORTS:
            port_reasons.append(
                f"unusual UDP traffic targeting TCP administrative port {dst_port}"
            )
        for label, port in (("destination", dst_port), ("source", src_port)):
            if port in SUSPICIOUS_PORTS:
                port_reasons.append(
                    f"{label} port {port} ({SUSPICIOUS_PORTS[port]})"
                )

        if port_reasons:
            points = 30.0 if len(port_reasons) > 1 else 25.0
            hint = "Possible Suspicious Port or Protocol Activity"
            detail = "Suspicious protocol/port combination: " + "; ".join(port_reasons) + "."
            matched_rules.append(
                {
                    "rule_id": "suspicious_protocol_port",
                    "title": "Suspicious Protocol or Port Combination",
                    "points": points,
                    "attack_hint": hint,
                    "detail": detail,
                }
            )
            evidence.append(detail)
            attack_hints.append(hint)

        raw_rule_score = sum(rule["points"] for rule in matched_rules)
        rule_score = min(100.0, round(raw_rule_score, 2))

        return {
            "rule_score": rule_score,
            "matched_rules": matched_rules,
            "evidence": evidence,
            "attack_hints": attack_hints,
            "context_notes": context_notes,
            "established_bidirectional_tcp": established_tcp,
            "likely_normal_web_traffic": normal_web_flow,
        }

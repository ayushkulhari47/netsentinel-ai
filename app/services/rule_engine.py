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
        tcp_flags = [str(flag).upper() for flag in flow.get("tcp_flags", [])] if isinstance(flow.get("tcp_flags"), list) else []

        matched_rules = []
        evidence = []
        attack_hints = []

        packet_rate = cleaned["packet_rate"]
        byte_rate = cleaned["byte_rate"]
        flow_bytes = cleaned["flow_bytes"]
        flow_packets = cleaned["flow_packets"]
        backward_packets = cleaned["backward_packets"]
        protocol = cleaned["protocol"]
        src_port = cleaned["source_port"]
        dst_port = cleaned["destination_port"]

        # 1. Unusually high packet rate
        if packet_rate >= self.high_packet_rate:
            is_extreme = packet_rate >= self.extreme_packet_rate
            points = 35.0 if is_extreme else 25.0
            syn_only = "S" in tcp_flags and "A" not in tcp_flags and backward_packets == 0
            hint = "Possible SYN/Packet Flood" if syn_only else "Possible High-Rate Packet Flood"
            detail = (
                f"Suspiciously high packet rate observed ({packet_rate:.1f} pkt/s, "
                f"threshold {self.high_packet_rate:.0f} pkt/s)"
            )
            if syn_only:
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
            is_extreme = byte_rate >= self.extreme_byte_rate
            points = 35.0 if is_extreme else 25.0
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
        }

"""Explainable hybrid detection engine combining ML, rules, and optional threat intel."""

import ipaddress
import numbers

from app.extensions import db
from app.ml.feature_schema import validate_flow_record
from app.ml.predict import DEFAULT_MODEL_PATH, predict_flow
from app.models import Alert
from app.services.rule_engine import RuleEngine


def map_risk_to_severity(threat_score):
    """Map a 0-100 risk score to low, medium, high, or critical severity."""
    score = float(threat_score)
    if score >= 75.0:
        return "critical"
    if score >= 50.0:
        return "high"
    if score >= 25.0:
        return "medium"
    return "low"


def _recommended_action_for_severity(severity):
    """Return cautious, actionable guidance matched to alert severity."""
    if severity == "critical":
        return (
            "Possible high-impact threat: isolate or rate-limit the source host if authorized, "
            "inspect firewall/endpoint logs immediately, and verify traffic legitimacy."
        )
    if severity == "high":
        return (
            "Suspicious activity warrants prompt triage: inspect recent connections from the "
            "source IP, review destination service logs, and confirm whether traffic is authorized."
        )
    if severity == "medium":
        return (
            "Monitor the source and destination endpoints closely, correlate with host logs, "
            "and verify whether the observed flow pattern is expected."
        )
    return "No immediate action required; continue baseline network monitoring."


def _evaluate_threat_intel(threat_intel):
    """Score optional pre-fetched threat intelligence metadata without external API calls."""
    if threat_intel is None:
        return 0.0, []
    if not isinstance(threat_intel, dict):
        raise ValueError("threat_intel must be a dictionary or None.")

    evidence = []
    points = 0.0

    reputation = str(threat_intel.get("reputation", "")).strip().lower()
    if reputation in {"private", "unknown", "clean"}:
        return 0.0, []

    malicious = bool(threat_intel.get("malicious", False))
    raw_score = threat_intel.get(
        "abuse_score",
        threat_intel.get("reputation_score", threat_intel.get("score")),
    )
    provider = threat_intel.get("provider", threat_intel.get("source", "provider"))
    categories = threat_intel.get("categories") or []

    score_val = None
    if isinstance(raw_score, numbers.Real) and not isinstance(raw_score, bool):
        score_val = max(0.0, min(100.0, float(raw_score)))
        if score_val >= 75.0:
            points = 30.0
        elif score_val >= 40.0:
            points = 20.0
        elif score_val > 0.0:
            points = 10.0

    if reputation == "reported" and points < 25.0:
        points = 25.0
    elif reputation == "suspicious" and points < 15.0:
        points = 15.0
    elif malicious and points < 25.0:
        points = 25.0

    if points > 0.0:
        score_text = f" (abuse score {score_val:.0f}/100)" if score_val is not None else ""
        cat_text = (
            f" in categories: {', '.join(str(c) for c in categories)}"
            if isinstance(categories, list) and categories
            else ""
        )
        if reputation in {"reported", "suspicious"}:
            evidence.append(
                f"Endpoint was {reputation} by the provider ({provider}){score_text}{cat_text}."
            )
        else:
            evidence.append(
                f"Provided {provider} metadata flagged this endpoint as potentially "
                f"suspicious{score_text}{cat_text}."
            )

    return points, evidence


def _validate_optional_ip(value, field_name):
    """Validate an IP address if present on the flow dictionary."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a valid IP address string.")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address.") from exc


class DetectionEngine:
    """Combines IsolationForest predictions, rule heuristics, and optional threat intel."""

    def __init__(
        self,
        model_path=DEFAULT_MODEL_PATH,
        model_bundle=None,
        rule_engine=None,
        threat_intel_service=None,
        suspicious_threshold=25.0,
    ):
        """Initialize the detection engine with local ML path and rule engine."""
        self.model_path = model_path
        self._model_bundle = model_bundle
        self.rule_engine = rule_engine if rule_engine is not None else RuleEngine()
        self.threat_intel_service = threat_intel_service
        self.suspicious_threshold = float(suspicious_threshold)

    def _run_ml(self, cleaned_flow):
        """Run local IsolationForest prediction, handling missing models gracefully."""
        try:
            ml_result = predict_flow(
                cleaned_flow,
                model_path=self.model_path,
                model_bundle=self._model_bundle,
            )
            return True, ml_result
        except (FileNotFoundError, OSError, EOFError):
            return False, {
                "anomaly_score": 0.0,
                "prediction": "unavailable",
                "confidence": 0.5,
            }

    def analyze_flow(self, flow, threat_intel=None, persist=True):
        """Analyze a network flow, compute risk/severity, and optionally persist Alerts."""
        if not isinstance(flow, dict):
            raise ValueError("Flow must be a dictionary.")

        cleaned_flow = validate_flow_record(flow)
        source_ip = _validate_optional_ip(flow.get("source_ip"), "source_ip")
        destination_ip = _validate_optional_ip(flow.get("destination_ip"), "destination_ip")

        ml_available, ml_result = self._run_ml(cleaned_flow)
        rule_result = self.rule_engine.evaluate(flow)

        effective_intel = threat_intel
        if effective_intel is None and self.threat_intel_service is not None and source_ip is not None:
            effective_intel = self.threat_intel_service.lookup_ip(source_ip)

        intel_points, intel_evidence = _evaluate_threat_intel(effective_intel)

        evidence = []
        ml_points = 0.0
        if ml_available:
            if ml_result["prediction"] == "anomaly":
                # Base 30 points for IsolationForest outlier, scaled up to 45 by confidence.
                ml_points = 30.0 + max(0.0, (ml_result["confidence"] - 0.5) * 30.0)
                evidence.append(
                    f"IsolationForest flagged a possible statistical anomaly "
                    f"(anomaly_score={ml_result['anomaly_score']:.4f}, "
                    f"confidence={ml_result['confidence']:.2f})."
                )
        else:
            evidence.append(
                "Local ML model is unavailable; assessment used heuristic rules only."
            )

        evidence.extend(rule_result["evidence"])
        evidence.extend(intel_evidence)

        combined_score = ml_points + rule_result["rule_score"] + intel_points
        threat_score = round(min(100.0, max(0.0, combined_score)), 2)
        severity = map_risk_to_severity(threat_score)
        is_suspicious = threat_score >= self.suspicious_threshold

        # Combine ML confidence with corroborating rule/intel signals into [0.0, 1.0].
        signal_count = (
            (1 if ml_available and ml_result["prediction"] == "anomaly" else 0)
            + len(rule_result["matched_rules"])
            + (1 if intel_points > 0 else 0)
        )
        if not is_suspicious:
            confidence = round(ml_result["confidence"] if ml_available else 0.5, 4)
            attack_type = "Normal Network Flow"
            explanation = (
                "No suspicious indicators observed; flow metrics remain within normal "
                "baseline thresholds."
            )
        else:
            base_conf = ml_result["confidence"] if ml_available else 0.55
            confidence = round(min(0.99, max(base_conf, 0.5 + 0.12 * signal_count)), 4)

            if rule_result["attack_hints"]:
                attack_type = rule_result["attack_hints"][0]
            elif ml_available and ml_result["prediction"] == "anomaly":
                attack_type = "Possible Anomalous Network Flow"
            else:
                attack_type = "Possible Suspicious Network Activity"

            explanation = (
                f"{attack_type} ({severity} risk, score {threat_score:.1f}/100): "
                + " ".join(evidence)
            )

        recommended_action = _recommended_action_for_severity(severity)

        persisted_alert = None
        if persist and is_suspicious:
            if source_ip is None or destination_ip is None:
                raise ValueError(
                    "source_ip and destination_ip are required to persist a suspicious Alert."
                )
            alert = Alert(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=cleaned_flow["source_port"],
                destination_port=cleaned_flow["destination_port"],
                protocol=cleaned_flow["protocol"],
                attack_type=attack_type,
                severity=severity,
                anomaly_score=ml_result["anomaly_score"],
                threat_score=threat_score,
                confidence=confidence,
                explanation=explanation,
                status="open",
            )
            db.session.add(alert)
            db.session.commit()
            persisted_alert = alert.to_dict()

        return {
            "attack_type": attack_type,
            "severity": severity,
            "anomaly_score": ml_result["anomaly_score"],
            "threat_score": threat_score,
            "confidence": confidence,
            "evidence": evidence,
            "explanation": explanation,
            "recommended_action": recommended_action,
            "is_suspicious": is_suspicious,
            "ml_available": ml_available,
            "alert": persisted_alert,
        }

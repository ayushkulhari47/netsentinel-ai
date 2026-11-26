"""End-to-end monitoring pipeline connecting capture, aggregation, detection, and SQLite."""

from app.extensions import db
from app.models import Alert
from app.services.detection_engine import DetectionEngine
from app.services.flow_aggregator import FlowAggregator
from app.services.llm_explainer import LLMExplainer
from app.services.packet_capture import PacketCaptureService
from app.services.threat_intel import ThreatIntelService


class MonitoringService:
    """Orchestrates metadata-only packet ingestion, completed-flow analysis, and Alert storage."""

    def __init__(
        self,
        flow_aggregator=None,
        detection_engine=None,
        threat_intel_service=None,
        llm_explainer=None,
    ):
        """Initialize pipeline components without starting live capture automatically."""
        self.flow_aggregator = flow_aggregator if flow_aggregator is not None else FlowAggregator()
        self.threat_intel_service = (
            threat_intel_service if threat_intel_service is not None else ThreatIntelService()
        )
        self.detection_engine = (
            detection_engine if detection_engine is not None else DetectionEngine()
        )
        self.llm_explainer = llm_explainer if llm_explainer is not None else LLMExplainer()

        self._active_capture_service = None
        self.flows_analyzed = 0
        self.alerts_created = []
        self.assessments = []

    def _lookup_optional_threat_intel(self, flow):
        """Look up threat intelligence only when an AbuseIPDB API key is configured."""
        if self.threat_intel_service is None or not self.threat_intel_service.is_configured():
            return None
        source_ip = flow.get("source_ip")
        if not source_ip:
            return None
        return self.threat_intel_service.lookup_ip(source_ip)

    def _enrich_alert_explanation(self, alert_dict, assessment, flow, threat_intel):
        """Generate sanitized explanation (OpenAI or fallback) without altering scores."""
        if not alert_dict or self.llm_explainer is None:
            return alert_dict

        structured = self.llm_explainer.explain(
            {
                **alert_dict,
                "rule_evidence": assessment.get("evidence", []),
            },
            threat_intel=threat_intel,
            flow_stats=flow,
        )

        alert_obj = db.session.get(Alert, alert_dict["id"])
        if alert_obj is not None:
            # Never alter ML score, threat_score, or severity.
            alert_obj.explanation = structured["summary"]
            db.session.commit()
            return alert_obj.to_dict()
        return alert_dict

    def _analyze_completed_flow(self, flow):
        """Run DetectionEngine, optional ThreatIntel, and explanation on one completed flow."""
        threat_intel = self._lookup_optional_threat_intel(flow)
        assessment = self.detection_engine.analyze_flow(
            flow,
            threat_intel=threat_intel,
            persist=True,
        )
        self.flows_analyzed += 1

        if assessment["is_suspicious"] and assessment["alert"] is not None:
            updated_alert = self._enrich_alert_explanation(
                assessment["alert"],
                assessment,
                flow,
                threat_intel,
            )
            assessment["alert"] = updated_alert
            self.alerts_created.append(updated_alert)

        self.assessments.append(assessment)
        return assessment

    def ingest_packet(self, packet_metadata):
        """Ingest one packet metadata dict and analyze any flows that have expired."""
        self.flow_aggregator.add_packet(packet_metadata)
        expired_flows = self.flow_aggregator.flush_expired(
            current_time=packet_metadata.get("timestamp")
        )
        return [self._analyze_completed_flow(flow) for flow in expired_flows]

    def flush_and_analyze(self):
        """Flush all remaining flows as completed and analyze each one."""
        completed_flows = self.flow_aggregator.flush_all()
        return [self._analyze_completed_flow(flow) for flow in completed_flows]

    def process_packets(self, packets, flush=True):
        """Process an iterable of packet metadata dicts through the full pipeline."""
        packets_processed = 0
        for packet in packets:
            self.ingest_packet(packet)
            packets_processed += 1

        if flush:
            self.flush_and_analyze()

        return {
            "mode": "batch",
            "packets_processed": packets_processed,
            "flows_analyzed": self.flows_analyzed,
            "alerts_created": len(self.alerts_created),
            "alerts": list(self.alerts_created),
            "assessments": list(self.assessments),
        }

    def request_stop(self):
        """Request graceful stop for an active live capture session."""
        if self._active_capture_service is not None:
            self._active_capture_service.request_stop()

    def run_live(
        self,
        live=False,
        interface=None,
        bpf_filter=None,
        packet_limit=None,
        timeout=None,
        sniff_fn=None,
    ):
        """Run controlled live packet capture (requires live=True) and analyze completed flows."""
        if live is not True:
            raise PermissionError(
                "Refusing to run live monitoring without explicit live=True authorization."
            )

        capture_service = PacketCaptureService(
            flow_aggregator=self.flow_aggregator,
            interface=interface,
            bpf_filter=bpf_filter,
            packet_limit=packet_limit,
            timeout=timeout,
            sniff_fn=sniff_fn,
        )
        self._active_capture_service = capture_service
        try:
            capture_result = capture_service.capture_live(live=True)
        finally:
            self._active_capture_service = None

        for completed_flow in capture_result["flows"]:
            self._analyze_completed_flow(completed_flow)

        return {
            "mode": "live",
            "packets_seen": capture_result["packets_seen"],
            "packets_processed": capture_result["packets_processed"],
            "packets_ignored": capture_result["packets_ignored"],
            "flows_analyzed": self.flows_analyzed,
            "alerts_created": len(self.alerts_created),
            "alerts": list(self.alerts_created),
            "assessments": list(self.assessments),
            "interrupted": capture_result["interrupted"],
        }

"""SQLAlchemy database models for NetSentinel AI."""

from datetime import datetime, timezone
from app.extensions import db


def utc_now():
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


class Alert(db.Model):
    """Represents a detected cybersecurity threat alert."""

    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(16), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)
    anomaly_score = db.Column(db.Float, nullable=False, default=0.0)
    threat_score = db.Column(db.Float, nullable=False, default=0.0)
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    explanation = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(20), nullable=False, default="open", index=True)

    def to_dict(self):
        """Serialize the Alert instance to a JSON-friendly dictionary."""
        ts = self.timestamp
        if ts is not None and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return {
            "id": self.id,
            "timestamp": ts.isoformat() if ts else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "anomaly_score": self.anomaly_score,
            "threat_score": self.threat_score,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "status": self.status,
        }

    def __repr__(self):
        return (
            f"<Alert id={self.id} attack_type={self.attack_type!r} "
            f"severity={self.severity!r} source_ip={self.source_ip!r}>"
        )

"""
a2zsoc_beacon_bridge.py - A2Z SOC Telemetry Bridge for API Beacon Radar
Orchestrates real-time webhook covert channel inspection, cryptographic audit chaining,
and telemetry exports.
Zero external dependencies (Python 3.10+ standard library).
"""

import hashlib
import json
import time
from typing import Dict, List, Optional
from .models import (
    WebhookEventEnvelope,
    RadarInspectionDecision,
)
from .covert_channel_sentinel import CovertChannelSentinel


class A2ZSocBeaconBridge:
    """Institutional bridge orchestrating API Beacon Radar inline sensor deployments."""

    def __init__(self, sentinel: Optional[CovertChannelSentinel] = None):
        self.sentinel = sentinel or CovertChannelSentinel()
        self.telemetry_log: List[Dict] = []
        self._prev_audit_hash = "GENESIS_API_BEACON_RADAR_00000000"

    def inspect_and_log(self, envelope: WebhookEventEnvelope) -> RadarInspectionDecision:
        """
        Inspects an incoming webhook and anchors decision into chained SHA-256 audit log.
        """
        decision = self.sentinel.inspect_webhook(envelope)

        chain_payload = {
            "prev_hash": self._prev_audit_hash,
            "decision_id": decision.decision_id,
            "event_id": envelope.event_id,
            "verdict": decision.verdict,
            "threat_score": decision.composite_threat_score,
            "timestamp": decision.timestamp,
        }
        current_hash = hashlib.sha256(json.dumps(chain_payload, sort_keys=True).encode()).hexdigest()
        self._prev_audit_hash = current_hash
        decision.audit_hash = current_hash

        self._emit_telemetry(decision, envelope)
        return decision

    def _emit_telemetry(self, decision: RadarInspectionDecision, envelope: WebhookEventEnvelope) -> None:
        telemetry_event = {
            "event_type": "API_RADAR_INSPECTION_DECISION",
            "decision_id": decision.decision_id,
            "event_id": envelope.event_id,
            "provider": envelope.provider,
            "verdict": decision.verdict,
            "threat_score": decision.composite_threat_score,
            "latency_us": decision.execution_latency_us,
            "audit_hash": decision.audit_hash,
            "timestamp": decision.timestamp,
        }
        self.telemetry_log.append(telemetry_event)

    def get_telemetry_events(self) -> List[Dict]:
        return list(self.telemetry_log)

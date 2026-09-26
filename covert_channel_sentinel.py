"""
covert_channel_sentinel.py - Real-Time API Gateway Covert Channel Sentinel
Fuses inter-arrival timing statistics and payload entropy scanning into sub-millisecond
quarantine and drop verdicts.
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
from .payload_entropy_scanner import PayloadEntropyScanner
from .inter_arrival_analyzer import InterArrivalAnalyzer


class CovertChannelSentinel:
    """Inline inspection sensor evaluating financial webhooks for C2 channels."""

    def __init__(
        self,
        entropy_scanner: Optional[PayloadEntropyScanner] = None,
        iat_analyzer: Optional[InterArrivalAnalyzer] = None,
    ):
        self.entropy_scanner = entropy_scanner or PayloadEntropyScanner()
        self.iat_analyzer = iat_analyzer or InterArrivalAnalyzer()

    def inspect_webhook(self, envelope: WebhookEventEnvelope) -> RadarInspectionDecision:
        """
        Executes real-time dual-vector inspection and generates a security verdict.
        """
        t0 = time.perf_counter()

        # 1. Payload & Metadata Entropy Analysis
        stego_result = self.entropy_scanner.scan_envelope(envelope)

        # 2. Statistical Inter-Arrival Timing Analysis
        beacon_result = self.iat_analyzer.record_and_analyze(
            source_id=envelope.client_source_id,
            timestamp=envelope.timestamp,
        )

        # 3. Composite Threat Calculation
        stego_weight = 0.85 if stego_result.is_steganography_detected else 0.10
        beacon_weight = beacon_result.beacon_confidence if beacon_result.is_beacon_detected else 0.05
        
        composite_score = min(1.0, (0.60 * stego_weight) + (0.40 * beacon_weight))

        # 4. Adjudicate Verdict
        if stego_result.is_steganography_detected and beacon_result.is_beacon_detected:
            verdict = "DROP_ALERT"
        elif stego_result.is_steganography_detected or composite_score >= 0.55:
            verdict = "QUARANTINE_WEBHOOK"
        else:
            verdict = "ALLOW"

        t1 = time.perf_counter()
        latency_us = (t1 - t0) * 1_000_000.0

        now = int(envelope.timestamp)
        decision_id = f"DEC-RADAR-{hashlib.sha256(f'{envelope.event_id}:{now}'.encode()).hexdigest()[:12]}"

        audit_payload = {
            "decision_id": decision_id,
            "event_id": envelope.event_id,
            "verdict": verdict,
            "composite_score": composite_score,
            "stego": stego_result.is_steganography_detected,
            "beacon": beacon_result.is_beacon_detected,
            "timestamp": now,
        }
        audit_hash = hashlib.sha256(json.dumps(audit_payload, sort_keys=True).encode()).hexdigest()

        return RadarInspectionDecision(
            decision_id=decision_id,
            event_id=envelope.event_id,
            verdict=verdict,
            composite_threat_score=composite_score,
            beacon_analysis=beacon_result,
            stego_analysis=stego_result,
            execution_latency_us=latency_us,
            timestamp=now,
            audit_hash=audit_hash,
        )

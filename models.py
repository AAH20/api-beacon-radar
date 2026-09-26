"""
models.py - Domain Models for API Beacon Radar
Covert Financial Webhook & Open Banking Steganography Sentinel.
Zero external dependencies (Python 3.10+ standard library).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time


@dataclass(frozen=True)
class WebhookEventEnvelope:
    """Financial webhook or Open Banking API request."""
    event_id: str
    provider: str  # "STRIPE", "PLAID", "FDX_OPEN_BANKING", "ADYEN"
    endpoint_path: str
    headers: Dict[str, str] = field(default_factory=dict)
    payload_body: str = ""
    metadata_fields: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    client_source_id: str = "SRC-DEFAULT"


@dataclass
class BeaconAnalysisResult:
    """Inter-arrival time and jitter distribution metrics."""
    is_beacon_detected: bool
    beacon_confidence: float  # 0.0 to 1.0
    estimated_period_seconds: float
    coefficient_of_variation: float
    rationale: str

    def to_dict(self) -> Dict:
        return {
            "is_beacon_detected": self.is_beacon_detected,
            "beacon_confidence": round(self.beacon_confidence, 4),
            "estimated_period_seconds": round(self.estimated_period_seconds, 2),
            "coefficient_of_variation": round(self.coefficient_of_variation, 4),
            "rationale": self.rationale,
        }


@dataclass
class SteganographyAnalysisResult:
    """Entropy, character distribution, and payload anomaly metrics."""
    is_steganography_detected: bool
    max_entropy_found: float
    offending_field: Optional[str]
    extracted_blob_sample: Optional[str]
    rationale: str

    def to_dict(self) -> Dict:
        return {
            "is_steganography_detected": self.is_steganography_detected,
            "max_entropy_found": round(self.max_entropy_found, 4),
            "offending_field": self.offending_field,
            "extracted_blob_sample": self.extracted_blob_sample,
            "rationale": self.rationale,
        }


@dataclass
class RadarInspectionDecision:
    """Real-time gateway verdict for an incoming financial webhook."""
    decision_id: str
    event_id: str
    verdict: str  # "ALLOW", "QUARANTINE_WEBHOOK", "DROP_ALERT"
    composite_threat_score: float
    beacon_analysis: BeaconAnalysisResult
    stego_analysis: SteganographyAnalysisResult
    execution_latency_us: float
    timestamp: int
    audit_hash: str

    def to_dict(self) -> Dict:
        return {
            "decision_id": self.decision_id,
            "event_id": self.event_id,
            "verdict": self.verdict,
            "composite_threat_score": round(self.composite_threat_score, 4),
            "beacon_analysis": self.beacon_analysis.to_dict(),
            "stego_analysis": self.stego_analysis.to_dict(),
            "execution_latency_us": round(self.execution_latency_us, 2),
            "timestamp": self.timestamp,
            "audit_hash": self.audit_hash,
        }

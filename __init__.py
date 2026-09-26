"""
api-beacon-radar - Covert Financial Webhook & Open Banking Steganography Sentinel.
Zero external dependencies (Python 3.10+ standard library).
"""

from .models import (
    WebhookEventEnvelope,
    BeaconAnalysisResult,
    SteganographyAnalysisResult,
    RadarInspectionDecision,
)
from .payload_entropy_scanner import PayloadEntropyScanner, compute_shannon_entropy
from .inter_arrival_analyzer import InterArrivalAnalyzer
from .covert_channel_sentinel import CovertChannelSentinel
from .a2zsoc_beacon_bridge import A2ZSocBeaconBridge

__version__ = "1.0.0"

__all__ = [
    "WebhookEventEnvelope",
    "BeaconAnalysisResult",
    "SteganographyAnalysisResult",
    "RadarInspectionDecision",
    "PayloadEntropyScanner",
    "compute_shannon_entropy",
    "InterArrivalAnalyzer",
    "CovertChannelSentinel",
    "A2ZSocBeaconBridge",
]

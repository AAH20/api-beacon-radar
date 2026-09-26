"""
inter_arrival_analyzer.py - Statistical Inter-Arrival Time (IAT) & Jitter Analyzer
Detects algorithmic C2 beaconing in financial webhook streams via Coefficient of Variation (Cv)
and periodicity clustering.
Zero external dependencies (Python 3.10+ standard library).
"""

import math
from typing import Dict, List, Optional
from .models import BeaconAnalysisResult


class InterArrivalAnalyzer:
    """Detects periodic or jittered C2 beaconing in API webhook event streams."""

    def __init__(
        self,
        min_events_required: int = 4,
        max_history_window: int = 50,
        cv_beacon_threshold: float = 0.25,
    ):
        self.min_events_required = min_events_required
        self.max_history_window = max_history_window
        self.cv_beacon_threshold = cv_beacon_threshold
        # In-memory sliding window history: source_id -> list of float timestamps
        self.source_history: Dict[str, List[float]] = {}

    def record_and_analyze(self, source_id: str, timestamp: float) -> BeaconAnalysisResult:
        """
        Records a webhook arrival and evaluates inter-arrival time metrics.
        """
        if source_id not in self.source_history:
            self.source_history[source_id] = []

        history = self.source_history[source_id]
        history.append(timestamp)

        if len(history) > self.max_history_window:
            history.pop(0)

        if len(history) < self.min_events_required:
            return BeaconAnalysisResult(
                is_beacon_detected=False,
                beacon_confidence=0.0,
                estimated_period_seconds=0.0,
                coefficient_of_variation=1.0,
                rationale=f"Insufficient sample size ({len(history)}/{self.min_events_required} events required for IAT statistical modeling).",
            )

        # Compute inter-arrival deltas
        deltas = [history[i] - history[i-1] for i in range(1, len(history))]
        # Filter out 0.0 or negative deltas from identical millisecond submissions
        valid_deltas = [d for d in deltas if d > 0.001]

        if len(valid_deltas) < (self.min_events_required - 1):
            return BeaconAnalysisResult(
                is_beacon_detected=False,
                beacon_confidence=0.0,
                estimated_period_seconds=0.0,
                coefficient_of_variation=1.0,
                rationale="Duplicate or invalid arrival timestamps.",
            )

        mean_delta = sum(valid_deltas) / len(valid_deltas)
        variance = sum((d - mean_delta) ** 2 for d in valid_deltas) / len(valid_deltas)
        std_dev = math.sqrt(variance)

        # Coefficient of Variation: Cv = sigma / mu
        cv = (std_dev / mean_delta) if mean_delta > 0 else 1.0

        is_beacon = (cv <= self.cv_beacon_threshold)
        # Confidence scales inversely with Cv
        confidence = max(0.0, min(1.0, 1.0 - (cv / (self.cv_beacon_threshold * 2.0))))

        if is_beacon:
            rationale = (
                f"ALGORITHMIC BEACONING DETECTED: Low Coefficient of Variation (Cv={cv:.3f} <= {self.cv_beacon_threshold}) "
                f"across {len(valid_deltas)} intervals, with estimated period T={mean_delta:.2f}s (+/- {std_dev:.2f}s). "
                f"Statistical signature indicates automated C2 polling or scheduled beaconing."
            )
        else:
            rationale = (
                f"NATURAL TRAFFIC VARIANCE: High arrival variance (Cv={cv:.3f} > {self.cv_beacon_threshold}) "
                f"consistent with human or random business transaction distributions."
            )

        return BeaconAnalysisResult(
            is_beacon_detected=is_beacon,
            beacon_confidence=confidence,
            estimated_period_seconds=mean_delta,
            coefficient_of_variation=cv,
            rationale=rationale,
        )
